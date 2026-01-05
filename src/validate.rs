use anyhow::Result;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509Ref, X509StoreContext};
use crate::util::format_name_human;
use crate::print::print_bold;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

/// Verify `leaf` against the system trust store with optional intermediates `chain`.
/// Returns Ok(Ok(())) on success, Ok(Err(msg)) for a verify failure with human context,
/// or Err(e) for unexpected OpenSSL errors while setting up verification.
pub fn validate_chain(leaf: &X509Ref, chain: &[&X509Ref]) -> Result<Result<(), String>> {
    let mut builder = X509StoreBuilder::new()?;
    // Use OpenSSL's default CA locations (system trust store)
    builder.set_default_paths()?;
    let store = builder.build();

    let mut stack: Stack<X509> = Stack::new()?;
    for c in chain { stack.push((*c).to_owned())?; }

    let mut ctx = X509StoreContext::new()?;
    // Run the standard path validation. The closure is invoked by OpenSSL.
    let ok = ctx.init(&store, &leaf.to_owned(), &stack, |c| c.verify_cert());
    match ok {
        Ok(true) => Ok(Ok(())),
        Ok(false) => {
            let err = ctx.error();
            let depth = ctx.error_depth();
            let cert_snippet = ctx.current_cert().map(|cc| {
                let subj = format_name_human(cc.subject_name().entries());
                if subj.is_empty() { "<unknown subject>".to_string() } else { subj }
            }).unwrap_or_else(|| "<unknown certificate>".to_string());
            let msg = format!("{} (depth {} on {})", err, depth, cert_snippet);
            Ok(Err(msg))
        }
        Err(e) => Err(e.into()),
    }
}

pub fn validate_and_report(seq: &[&X509Ref], _unused: &[&X509Ref]) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);
    if let Some(leaf) = seq.first() {
        match validate_chain(leaf, &seq[1..]) {
            Ok(Ok(())) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
                write!(&mut stdout, "✅ the chain is valid")?;
                stdout.reset()?;
                writeln!(&mut stdout)?;
            }
            Ok(Err(msg)) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                print_bold(&mut stdout, "❌ the chain has issues:")?;
                writeln!(&mut stdout)?;
                writeln!(&mut stdout, "- {}", msg)?;
            }
            Err(e) => {
                stdout.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                print_bold(&mut stdout, "❌ the chain has issues:")?;
                writeln!(&mut stdout)?;
                writeln!(&mut stdout, "- validation error: {}", e)?;
            }
        }
    }
    Ok(())
}
