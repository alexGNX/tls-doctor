use openssl::x509::{X509Ref, X509};
use std::collections::{HashMap, HashSet};

// Best-effort chain ordering: pick a likely leaf (subject not used as issuer) and
// follow issuer->subject links until a self-signed root or a gap; return the
// ordered chain and any unused certificates (unrelated/orphaned).

pub fn order_chain_leaf_to_root(certs: &[X509]) -> (Vec<&X509Ref>, Vec<&X509Ref>) {
    let mut by_subject: HashMap<Vec<u8>, Vec<&X509Ref>> = HashMap::new();
    let mut all: Vec<&X509Ref> = Vec::new();
    for c in certs {
        let r = c.as_ref();
        all.push(r);
        let subj = r.subject_name().to_der().unwrap_or_default();
        by_subject.entry(subj).or_default().push(r);
    }
    let issuer_subjects: HashSet<Vec<u8>> = all
        .iter()
        .map(|c| c.issuer_name().to_der().unwrap_or_default())
        .collect();
    let mut candidate_leafs: Vec<&X509Ref> = Vec::new();
    for c in &all {
        let subj = c.subject_name().to_der().unwrap_or_default();
        if !issuer_subjects.contains(&subj) {
            candidate_leafs.push(*c);
        }
    }
    let leaf = candidate_leafs.first().copied().unwrap_or_else(|| all[0]);

    let mut seq: Vec<&X509Ref> = Vec::new();
    let mut used: HashSet<usize> = HashSet::new();
    let mut current = leaf;
    seq.push(current);
    used.insert(current as *const _ as usize);
    loop {
        let current_issuer = current.issuer_name().to_der().unwrap_or_default();
        let current_subject = current.subject_name().to_der().unwrap_or_default();
        if current_issuer == current_subject { break; }
        let next = by_subject.get(&current_issuer).and_then(|v| v.first().copied());
        match next {
            Some(n) => {
                if seq.iter().any(|c| std::ptr::eq(*c, n)) { break; }
                seq.push(n);
                current = n;
                used.insert(current as *const _ as usize);
            }
            None => break,
        }
    }
    let unused: Vec<&X509Ref> = all
        .into_iter()
        .filter(|c| !used.contains(&(*c as *const _ as usize)))
        .collect();
    (seq, unused)
}
