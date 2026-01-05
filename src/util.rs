use anyhow::Result;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::Id as KeyId;
use openssl::x509::{X509NameEntries, X509Ref};

/// Extract a subset of X.509 name attributes and map them to human labels
/// in a consistent order for display.
pub fn name_items(entries: X509NameEntries<'_>) -> Vec<(&'static str, String)> {
    let mut parts: Vec<(Nid, String)> = Vec::new();
    for e in entries {
        let nid = e.object().nid();
        if let Ok(val) = e.data().as_utf8() {
            match nid {
                Nid::COMMONNAME
                | Nid::ORGANIZATIONNAME
                | Nid::ORGANIZATIONALUNITNAME
                | Nid::COUNTRYNAME
                | Nid::STATEORPROVINCENAME
                | Nid::LOCALITYNAME => parts.push((nid, val.to_string())),
                _ => {}
            }
        }
    }
    let order = [
        Nid::COMMONNAME,
        Nid::ORGANIZATIONNAME,
        Nid::ORGANIZATIONALUNITNAME,
        Nid::COUNTRYNAME,
        Nid::STATEORPROVINCENAME,
        Nid::LOCALITYNAME,
    ];
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for nid in order {
        for (n, v) in parts.iter() {
            if *n == nid {
                let label = match nid {
                    Nid::COMMONNAME => "Common Name",
                    Nid::ORGANIZATIONNAME => "Organization",
                    Nid::ORGANIZATIONALUNITNAME => "Organizational Unit",
                    Nid::COUNTRYNAME => "Country",
                    Nid::STATEORPROVINCENAME => "State/Province",
                    Nid::LOCALITYNAME => "Locality",
                    _ => "",
                };
                out.push((label, v.clone()));
            }
        }
    }
    out
}

/// Render a compact single-line subject/issuer snippet; used in error messages.
pub fn format_name_human(entries: X509NameEntries<'_>) -> String {
    let mut parts: Vec<(Nid, String)> = Vec::new();
    for e in entries {
        let nid = e.object().nid();
        let data = e.data().as_utf8();
        if let Ok(val) = data {
            match nid {
                Nid::COMMONNAME
                | Nid::ORGANIZATIONNAME
                | Nid::ORGANIZATIONALUNITNAME
                | Nid::COUNTRYNAME
                | Nid::STATEORPROVINCENAME
                | Nid::LOCALITYNAME => parts.push((nid, val.to_string())),
                _ => {}
            }
        }
    }

    let mut out = String::new();
    let order = [
        Nid::COMMONNAME,
        Nid::ORGANIZATIONNAME,
        Nid::ORGANIZATIONALUNITNAME,
        Nid::COUNTRYNAME,
        Nid::STATEORPROVINCENAME,
        Nid::LOCALITYNAME,
    ];
    for nid in order {
        for (n, v) in parts.iter() {
            if *n == nid {
                if !out.is_empty() {
                    out.push_str(", ");
                }
                let label = match nid {
                    Nid::COMMONNAME => "Common Name",
                    Nid::ORGANIZATIONNAME => "Organization",
                    Nid::ORGANIZATIONALUNITNAME => "Organizational Unit",
                    Nid::COUNTRYNAME => "Country",
                    Nid::STATEORPROVINCENAME => "State/Province",
                    Nid::LOCALITYNAME => "Locality",
                    _ => "",
                };
                out.push_str(&format!("{}={}", label, v));
            }
        }
    }
    if out.is_empty() {
        if parts.is_empty() {
            return String::new();
        }
        return parts
            .into_iter()
            .map(|(n, v)| {
                let label = match n {
                    Nid::COMMONNAME => "Common Name",
                    Nid::ORGANIZATIONNAME => "Organization",
                    Nid::ORGANIZATIONALUNITNAME => "Organizational Unit",
                    Nid::COUNTRYNAME => "Country",
                    Nid::STATEORPROVINCENAME => "State/Province",
                    Nid::LOCALITYNAME => "Locality",
                    _ => "Other",
                };
                format!("{label} = {v}")
            })
            .collect::<Vec<_>>()
            .join(", ");
    }
    out
}

/// Return a colon-separated SHA-256 fingerprint (uppercase hex).
pub fn fingerprint_sha256(cert: &X509Ref) -> Result<String> {
    let d = cert.digest(MessageDigest::sha256())?;
    Ok(d.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":"))
}

/// Try to get the named curve for EC public keys (short or long name).
pub fn ec_curve_name(pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>) -> Option<String> {
    if pkey.id() != KeyId::EC { return None; }
    if let Ok(ec_key) = pkey.ec_key() {
        if let Some(nid) = ec_key.group().curve_name() {
            if let Ok(sn) = nid.short_name() { return Some(sn.to_string()); }
            if let Ok(ln) = nid.long_name() { return Some(ln.to_string()); }
            return Some(format!("NID({})", nid.as_raw()));
        }
    }
    None
}

/// Heuristic classification DV/OV/EV based on Subject attributes (no policy OIDs).
pub fn infer_cert_type(cert: &X509Ref) -> Option<&'static str> {
    let mut has_o = false;
    let mut has_sn = false;
    for e in cert.subject_name().entries() {
        let nid = e.object().nid();
        if nid == Nid::ORGANIZATIONNAME { has_o = true; }
        if nid == Nid::SERIALNUMBER { has_sn = true; }
    }
    if has_o && has_sn { Some("Extended Validation") }
    else if has_o { Some("Organization Validation") }
    else { Some("Domain Validation") }
}

/// Convenience: extract Subject Common Name (CN) if present.
pub fn subject_cn(cert: &X509Ref) -> Option<String> {
    for e in cert.subject_name().entries() {
        if e.object().nid() == Nid::COMMONNAME {
            if let Ok(s) = e.data().as_utf8() { return Some(s.to_string()); }
        }
    }
    None
}

/// Convenience: extract Issuer Common Name (CN) if present.
pub fn issuer_cn(cert: &X509Ref) -> Option<String> {
    for e in cert.issuer_name().entries() {
        if e.object().nid() == Nid::COMMONNAME {
            if let Ok(s) = e.data().as_utf8() { return Some(s.to_string()); }
        }
    }
    None
}
