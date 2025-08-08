use anyhow::{bail, Context, Result};
use openssl::x509::X509;
use reqwest::blocking::Client;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use x509_parser::prelude::*;

/// Build a best-effort certificate bundle (leaf -> root) starting from a leaf file.
/// Follows AIA caIssuers URIs to fetch intermediates (and possibly root) online.
pub fn build_bundle_from_leaf_file(input_path: &Path) -> Result<Vec<X509>> {
    let data = fs::read(input_path)
        .with_context(|| format!("failed to read input file {}", input_path.display()))?;
    let leaf = parse_single_cert_pem_or_der(&data)?;
    build_bundle_from_leaf(leaf)
}

pub fn write_pem_bundle(output_path: &Path, chain: &[X509]) -> Result<()> {
    let mut out = Vec::new();
    for cert in chain {
        let pem = cert.to_pem()?;
        out.extend_from_slice(&pem);
    }
    fs::write(output_path, &out)
        .with_context(|| format!("failed to write bundle to {}", output_path.display()))?;
    Ok(())
}

fn parse_single_cert_pem_or_der(data: &[u8]) -> Result<X509> {
    // Try PEM first (may contain multiple; take the first)
    if let Ok(stack) = X509::stack_from_pem(data) {
        if let Some(c) = stack.into_iter().next() {
            return Ok(c);
        }
    }
    // Then try DER
    let cert = X509::from_der(data).context("input is neither PEM nor DER certificate")?;
    Ok(cert)
}

fn aia_ca_issuers_urls(cert: &X509) -> Vec<String> {
    // Use x509-parser for robust AIA parsing
    let der = match cert.to_der() { Ok(d) => d, Err(_) => return vec![] };
    if let Ok((_, parsed)) = X509Certificate::from_der(&der) {
        for ext in parsed.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
                let mut urls = Vec::new();
                for ad in &aia.accessdescs {
                    // 1.3.6.1.5.5.7.48.2 = id-ad-caIssuers
                    if ad.access_method.to_id_string() == "1.3.6.1.5.5.7.48.2" {
                        if let GeneralName::URI(uri) = &ad.access_location {
                            urls.push(uri.to_string());
                        }
                    }
                }
                if !urls.is_empty() { return urls; }
            }
        }
    }
    vec![]
}

fn fetch_issuer_from_url(client: &Client, url: &str) -> Result<Vec<X509>> {
    let resp = client.get(url).send().with_context(|| format!("GET {} failed", url))?;
    if !resp.status().is_success() {
        bail!("{}: HTTP {}", url, resp.status());
    }
    let bytes = resp.bytes()?.to_vec();

    // Try X.509 DER
    if let Ok(cert) = X509::from_der(&bytes) {
        return Ok(vec![cert]);
    }

    // Try PEM (could be one or many)
    if let Ok(stack) = X509::stack_from_pem(&bytes) {
        return Ok(stack);
    }

    bail!("unrecognized certificate format from {}", url)
}

fn is_self_issued(cert: &X509) -> bool {
    cert.subject_name().to_der().ok() == cert.issuer_name().to_der().ok()
}

pub fn build_bundle_from_leaf(leaf: X509) -> Result<Vec<X509>> {
    let client = Client::builder()
        .user_agent("tls-doctor/1.0")
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let mut chain: Vec<X509> = vec![leaf];
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    // track subjects we have to avoid loops
    seen.insert(chain[0].subject_name().to_der().unwrap_or_default());

    loop {
        let current = chain.last().unwrap();
        // Stop at self-issued (likely root) to avoid infinite fetch
        if is_self_issued(current) { break; }

        let urls = aia_ca_issuers_urls(current);
        if urls.is_empty() {
            // No AIA; stop
            break;
        }

        let mut next_issuer: Option<X509> = None;
        for url in urls {
            if let Ok(candidates) = fetch_issuer_from_url(&client, &url) {
                // pick the first whose subject matches current.issuer
                let cur_iss = current.issuer_name().to_der().unwrap_or_default();
                for cand in candidates {
                    let subj = cand.subject_name().to_der().unwrap_or_default();
                    if subj == cur_iss {
                        next_issuer = Some(cand);
                        break;
                    }
                }
            }
            if next_issuer.is_some() { break; }
        }

        match next_issuer {
            Some(issuer) => {
                let subj = issuer.subject_name().to_der().unwrap_or_default();
                if seen.contains(&subj) {
                    // loop or duplicate
                    break;
                }
                chain.push(issuer);
                seen.insert(subj);
                continue;
            }
            None => break,
        }
    }

    Ok(chain)
}
