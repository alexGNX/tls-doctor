use anyhow::Result;
use openssl::x509::X509Ref;
use crate::util::{name_items, fingerprint_sha256, ec_curve_name, infer_cert_type, format_asn1_time};
use openssl::pkey::Id as KeyId;
use std::io::Write;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

pub fn print_bold<W: WriteColor>(w: &mut W, text: &str) -> Result<()> {
    w.set_color(ColorSpec::new().set_bold(true))?;
    write!(w, "{}", text)?;
    w.reset()?;
    Ok(())
}

pub fn print_bold_blue<W: WriteColor>(w: &mut W, text: &str) -> Result<()> {
    w.set_color(ColorSpec::new().set_bold(true).set_fg(Some(Color::Blue)))?;
    write!(w, "{}", text)?;
    w.reset()?;
    Ok(())
}

// Render the ordered chain with a simple "is issued by ->" separator for readability.
pub fn print_chain_with_separator(seq: &[&X509Ref]) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);
    for (i, cert) in seq.iter().enumerate() {
        print_cert_info_to(&mut stdout, i + 1, cert)?;
        if i + 1 < seq.len() {
            writeln!(&mut stdout, "is issued by ->")?;
        }
    }
    Ok(())
}

// Print a concise, human-oriented view: Subject/Issuer (selected attributes),
// key algorithm and size, and a SHA-256 fingerprint.
pub fn print_cert_info(idx: usize, cert: &X509Ref) -> Result<()> {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);
    print_cert_info_to(&mut stdout, idx, cert)
}

fn print_cert_info_to<W: WriteColor>(w: &mut W, idx: usize, cert: &X509Ref) -> Result<()> {
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

    writeln!(w, "[{}]", idx)?;
    
    write!(w, "  ")?;
    print_bold(w, "Subject:")?;
    writeln!(w)?;

    if let Some(kind) = infer_cert_type(cert) {
        write!(w, "    - ")?;
        print_bold(w, "Type:")?;
        write!(w, " ")?;
        print_bold_blue(w, &kind)?;
        writeln!(w)?;
    }
    for (label, value) in subject_items {
        write!(w, "    - ")?;
        print_bold(w, &format!("{}:", label))?;
        write!(w, " ")?;
        print_bold_blue(w, &value)?;
        writeln!(w)?;
    }
    print_bold(w, "  Issuer:")?;
    writeln!(w, "  ")?;
    for (label, value) in issuer_items {
        write!(w, "    - ")?;
        print_bold(w, &format!("{}:", label))?;
        write!(w, " ")?;
        print_bold_blue(w, &value)?;
        writeln!(w)?;
    }
    print_bold(w, "  Validity:")?;
    writeln!(w)?;
    write!(w, "    - ")?;
    print_bold(w, "Not Before:")?;
    write!(w, " ")?;
    print_bold_blue(w, &format_asn1_time(cert.not_before()))?;
    writeln!(w)?;
    write!(w, "    - ")?;
    print_bold(w, "Not After: ")?;
    write!(w, " ")?;
    print_bold_blue(w, &format_asn1_time(cert.not_after()))?;
    writeln!(w)?;

    print_bold(w, "  Public Key:")?;
    write!(w, " ")?;
    print_bold_blue(w, &format!("{} {} bits", alg, key_bits))?;
    writeln!(w)?;

    print_bold(w, "  SHA-256 Fingerprint:")?;
    write!(w, " ")?;
    print_bold_blue(w, &fp)?;
    writeln!(w)?;
    writeln!(w)?;

    Ok(())
}
