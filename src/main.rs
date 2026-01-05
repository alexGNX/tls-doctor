use anyhow::{Context, Result};
use openssl::hash::MessageDigest;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::{X509Ref, X509};
use std::net::TcpStream;
use std::path::PathBuf;
use clap::Parser;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

mod cli;
mod chain;
mod validate;
mod print;
mod util;
mod scaffold;

use crate::chain::order_chain_leaf_to_root;
use crate::cli::{Cli, Command};
use crate::print::{print_cert_info, print_chain_with_separator, print_bold};
use crate::validate::{validate_and_report, validate_chain};
use crate::util::{issuer_cn, subject_cn};
use crate::scaffold::{build_bundle_from_leaf_file, write_pem_bundle};

/// Entry point wiring CLI, network handshake, printing, and validation.

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
    Command::Diag(args) => run_diag(args)?,
    Command::Scaffold(args) => run_scaffold(args)?,
    }

    Ok(())
}

fn run_diag(args: &crate::cli::DiagArgs) -> Result<()> {
    if let Some(file) = &args.file {
        return run_with_file(file);
    }

    let server = args.server.as_ref().expect("clap enforces one of --server/--file");
    let addr = format!("{}:{}", server, args.port);
    let tcp = TcpStream::connect(&addr)
        .with_context(|| format!("failed to connect to {}", addr))?;

    let mut builder = SslConnector::builder(SslMethod::tls())?;
    if args.insecure {
        builder.set_verify(SslVerifyMode::NONE);
    }
    let connector = builder.build();

    // For SNI and hostname verification, pass the hostname (not host:port)
    let hostname = server.as_str();
    let ssl_stream = connector
        .connect(hostname, tcp)
        .with_context(|| format!("TLS handshake with {} failed", addr))?;

    // Grab the peer certificate chain (includes leaf). Some servers may not send intermediates.
    let chain = ssl_stream.ssl().peer_cert_chain();

    let mut stdout = StandardStream::stdout(ColorChoice::Auto);
    writeln!(&mut stdout, "--- Certificate chain (leaf -> root) ---")?;

    // Build the sequence leaf -> chain (skipping duplicate leaf if present)
    let leaf_opt = ssl_stream.ssl().peer_certificate();
    let leaf_fp = leaf_opt
        .as_ref()
        .and_then(|c| c.digest(MessageDigest::sha256()).ok())
        .map(|d| d.to_vec());

    let mut seq: Vec<&X509Ref> = Vec::new();
    if let Some(leaf) = leaf_opt.as_ref() {
        seq.push(leaf);
    }
    if let Some(stack) = chain {
        for cert in stack {
            if let Some(ref lf) = leaf_fp {
                if let Ok(d) = cert.digest(MessageDigest::sha256()) {
                    if &d[..] == &lf[..] {
                        continue;
                    }
                }
            }
            seq.push(cert);
        }
    }

    print_chain_with_separator(&seq)?;
    validate_and_report(&seq, &[])?;

    // Drop connection immediately after printing the chain.

    Ok(())
}

// Offline mode: read a PEM bundle, build a best-effort chain and report issues.
fn run_with_file(path: &PathBuf) -> Result<()> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read PEM bundle from {}", path.display()))?;
    let certs = X509::stack_from_pem(&data)
        .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", path.display());
    }

    // Order certificates: attempt to assemble a leaf->root chain from the set
    let (seq, unused) = order_chain_leaf_to_root(&certs);

    let mut stdout = StandardStream::stdout(ColorChoice::Auto);
    writeln!(&mut stdout, "--- Certificate chain (leaf -> root) ---")?;
    print_chain_with_separator(&seq)?;
    // Also display unrelated certificates, if any, without "issued by"
    let mut issues: Vec<String> = Vec::new();
    let mut next_index = seq.len();
    if !unused.is_empty() {
        for cert in &unused {
            next_index += 1;
            print_cert_info(next_index, cert)?;
        }
    }

    // Evaluate bundle consistency (unrelated, incomplete, self-verify) and system trust
    // Unused/orphan certs in the bundle
    if !unused.is_empty() {
        let labels = unused
            .iter()
            .map(|c| subject_cn(c).map(|cn| format!("CN={}", cn)).unwrap_or_else(|| "<unknown>".to_string()))
            .collect::<Vec<_>>()
            .join(", ");
        issues.push(format!("bundle contains unrelated certificate(s): {}", labels));
    }

    if let Some(last) = seq.last() {
        let subj = last.subject_name().to_der().unwrap_or_default();
        let iss = last.issuer_name().to_der().unwrap_or_default();
        if subj != iss {
            let label = issuer_cn(last).map(|cn| format!("CN={}", cn)).unwrap_or_else(|| "<unknown>".to_string());
            issues.push(format!("chain incomplete: missing issuer {}", label));
        } else if let Ok(pk) = last.public_key() {
            if last.verify(&pk).is_err() {
                issues.push("root certificate signature does not verify itself".to_string());
            }
        }
    }

    if let Some(leaf) = seq.first() {
        match validate_chain(leaf, &seq[1..]) {
            Ok(Ok(())) => {
                if issues.is_empty() {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
                    write!(&mut stdout, "✅ the chain is valid")?;
                    stdout.reset()?;
                    writeln!(&mut stdout)?;
                } else {
                    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                    print_bold(&mut stdout, "❌ the chain has issues:")?;
                    writeln!(&mut stdout)?;
                    for i in &issues { writeln!(&mut stdout, "- {}", i)?; }
                }
            }
            Ok(Err(msg)) => {
                issues.push(msg);
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                print_bold(&mut stdout, "❌ the chain has issues:")?;
                writeln!(&mut stdout)?;
                for i in &issues { writeln!(&mut stdout, "- {}", i)?; }
            }
            Err(e) => {
                issues.push(format!("validation error: {}", e));
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                print_bold(&mut stdout, "❌ the chain has issues:")?;
                writeln!(&mut stdout)?;
                for i in &issues { writeln!(&mut stdout, "- {}", i)?; }
            }
        }
    } else {
        stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
        print_bold(&mut stdout, "❌ the chain has issues:")?;
        writeln!(&mut stdout)?;
        writeln!(&mut stdout, "- no certificates parsed")?;
    }

    Ok(())
}

// Scaffold subcommand: acknowledge input and output; implementation to follow.
fn run_scaffold(args: &crate::cli::ScaffoldArgs) -> Result<()> {
    let chain = build_bundle_from_leaf_file(&args.input)?;
    write_pem_bundle(&args.output, &chain)?;
    println!("wrote {} certificate(s) to {}", chain.len(), args.output.display());
    Ok(())
}

#[cfg(test)]
mod tests;

