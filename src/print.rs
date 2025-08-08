use anyhow::Result;
use openssl::x509::X509Ref;
use crate::util::{name_items, fingerprint_sha256, ec_curve_name, infer_cert_type, BOLD, BLUE, RESET};
use openssl::pkey::Id as KeyId;

// Render the ordered chain with a simple "is issued by ->" separator for readability.
pub fn print_chain_with_separator(seq: &[&X509Ref]) -> Result<()> {
    for (i, cert) in seq.iter().enumerate() {
        print_cert_info(i + 1, cert)?;
        if i + 1 < seq.len() {
            println!("is issued by ->");
        }
    }
    Ok(())
}

// Print a concise, human-oriented view: Subject/Issuer (selected attributes),
// key algorithm and size, and a SHA-256 fingerprint.
pub fn print_cert_info(idx: usize, cert: &X509Ref) -> Result<()> {
    let subject_items = name_items(cert.subject_name().entries());
    let issuer_items = name_items(cert.issuer_name().entries());

    let pkey = cert.public_key()?;
    let key_bits = pkey.bits();
    let alg = match pkey.id() {
        KeyId::RSA => "RSA".to_string(),
        KeyId::EC => format!("EC{}", ec_curve_name(&pkey).map(|c| format!(" ({})", c)).unwrap_or_default()),
        KeyId::ED25519 => "Ed25519".to_string(),
        KeyId::ED448 => "Ed448".to_string(),
        KeyId::X25519 => "X25519".to_string(),
        KeyId::X448 => "X448".to_string(),
        other => format!("{:?}", other),
    };

    // Prefer SHA-256 which is widely used by modern tooling
    let fp = fingerprint_sha256(cert)?;

    println!("[{}]", idx);
    println!("  {BOLD}Subject:{RESET}");
    if let Some(kind) = infer_cert_type(cert) {
        println!("    - {BOLD}Type:{RESET} {BLUE}{}{RESET}", kind);
    }
    for (label, value) in subject_items {
        println!("    - {BOLD}{}:{RESET} {BLUE}{}{RESET}", label, value);
    }
    println!("  {BOLD}Issuer:{RESET}  ");
    for (label, value) in issuer_items {
        println!("    - {BOLD}{}:{RESET} {BLUE}{}{RESET}", label, value);
    }
    println!("  {BOLD}Public Key:{RESET} {BLUE}{} {} bits{RESET}", alg, key_bits);
    println!("  {BOLD}SHA-256 Fingerprint:{RESET} {BLUE}{}{RESET}", fp);
    println!();

    Ok(())
}
