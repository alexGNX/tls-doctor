use super::*;
use openssl::nid::Nid;
use crate::util::infer_cert_type;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};

fn gen_key() -> PKey<Private> {
    let rsa = Rsa::generate(2048).expect("rsa");
    PKey::from_rsa(rsa).expect("pkey")
}

fn build_name(cn: &str, org: Option<&str>, serial_attr: Option<&str>) -> openssl::x509::X509Name {
    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
    if let Some(o) = org { nb.append_entry_by_nid(Nid::ORGANIZATIONNAME, o).unwrap(); }
    if let Some(sn) = serial_attr { nb.append_entry_by_nid(Nid::SERIALNUMBER, sn).unwrap(); }
    nb.build()
}

fn build_cert(subject_cn: &str, org: Option<&str>, serial_attr: Option<&str>, issuer_cert: Option<&X509>, issuer_key: &PKey<Private>, subject_key: &PKey<Private>) -> X509 {
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let mut bn = BigNum::new().unwrap();
    bn.rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false).unwrap();
    let asn1 = Asn1Integer::from_bn(&bn).unwrap();
    b.set_serial_number(&asn1).unwrap();

    let subject_name = build_name(subject_cn, org, serial_attr);
    b.set_subject_name(&subject_name).unwrap();
    if let Some(ic) = issuer_cert {
        b.set_issuer_name(ic.subject_name()).unwrap();
    } else {
        b.set_issuer_name(&subject_name).unwrap();
    }

    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    b.set_pubkey(subject_key).unwrap();

    // Sign with issuer key or self-key
    let sign_key = if issuer_cert.is_some() { issuer_key } else { subject_key };
    b.sign(sign_key, MessageDigest::sha256()).unwrap();
    b.build()
}

#[test]
fn test_order_chain_leaf_to_root_basic() {
    let root_key = gen_key();
    let int_key = gen_key();
    let leaf_key = gen_key();

    let root = build_cert("RootCA", Some("RootOrg"), None, None, &root_key, &root_key);
    let interm = build_cert("IntermCA", Some("IntermOrg"), None, Some(&root), &root_key, &int_key);
    let leaf = build_cert("Leaf", None, None, Some(&interm), &int_key, &leaf_key);

    // Provide in shuffled order
    let input = vec![interm.clone(), leaf.clone(), root.clone()];
    let (ordered, unused) = order_chain_leaf_to_root(&input);
    assert_eq!(unused.len(), 0);
    assert_eq!(ordered.len(), 3);
    assert_eq!(subject_cn(ordered[0]).unwrap(), "Leaf");
    assert_eq!(subject_cn(ordered[1]).unwrap(), "IntermCA");
    assert_eq!(subject_cn(ordered[2]).unwrap(), "RootCA");
}

#[test]
fn test_order_chain_with_unrelated() {
    let root_key = gen_key();
    let int_key = gen_key();
    let leaf_key = gen_key();
    let other_key = gen_key();

    let root = build_cert("RootCA", None, None, None, &root_key, &root_key);
    let interm = build_cert("IntermCA", None, None, Some(&root), &root_key, &int_key);
    let leaf = build_cert("Leaf", None, None, Some(&interm), &int_key, &leaf_key);
    let other = build_cert("OtherRoot", None, None, None, &other_key, &other_key);

    let input = vec![leaf.clone(), other.clone(), interm.clone(), root.clone()];
    let (ordered, unused) = order_chain_leaf_to_root(&input);
    assert_eq!(ordered.len(), 3);
    assert_eq!(subject_cn(ordered[0]).unwrap(), "Leaf");
    assert_eq!(unused.len(), 1);
    assert_eq!(subject_cn(unused[0]).unwrap(), "OtherRoot");
}

#[test]
fn test_cn_extract_and_type() {
    let k = gen_key();
    let ca = build_cert("CA", Some("Org"), None, None, &k, &k);
    let leaf_dv = build_cert("LeafDV", None, None, Some(&ca), &k, &k);
    let leaf_ov = build_cert("LeafOV", Some("Org"), None, Some(&ca), &k, &k);
    let leaf_ev = build_cert("LeafEV", Some("Org"), Some("SN123"), Some(&ca), &k, &k);

    assert_eq!(subject_cn(leaf_dv.as_ref()).unwrap(), "LeafDV");
    assert_eq!(issuer_cn(leaf_dv.as_ref()).unwrap(), "CA");

    assert_eq!(infer_cert_type(leaf_dv.as_ref()).unwrap(), "Domain Validation");
    assert_eq!(infer_cert_type(leaf_ov.as_ref()).unwrap(), "Organization Validation");
    assert_eq!(infer_cert_type(leaf_ev.as_ref()).unwrap(), "Extended Validation");
}
