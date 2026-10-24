//! The combiner on arbitrary policies, secrets and contexts: `Policy::new` and `combine` never
//! panic, accept exactly what the documented rules accept, and `combine` returns SHA3-256 of the
//! documented v1 encoding, recomputed here. `qkd_pqc_v2` is checked the same way. Contexts and
//! QKD keys are cut to 1024 bytes, because OSS Verify asks for bounded sizes (fuzz/README.md).
//!
//! Each property below names a mutant that makes it fail (OSS Verify's skill, section 3.4): a
//! one-line change, and an input from `combiner_seed_corpus.zip` in the enrollment directory.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::combiner::{
    qkd_pqc_v2, CombinerError, Mechanism, Policy, Secret, COMBINER_LABEL, MIN_SECRET_LEN,
    PQTG_MIXING_LABEL,
};
use paraxiom_pqc_fuzz::{bounded, split};
use sha3::{Digest, Sha3_256};

const ALL: [Mechanism; 5] = [
    Mechanism::Qkd,
    Mechanism::MlKem512,
    Mechanism::MlKem768,
    Mechanism::MlKem1024,
    Mechanism::PreShared,
];

fn id(m: Mechanism) -> u8 {
    match m {
        Mechanism::Qkd => 0x01,
        Mechanism::MlKem512 => 0x10,
        Mechanism::MlKem768 => 0x11,
        Mechanism::MlKem1024 => 0x12,
        Mechanism::PreShared => 0x20,
        _ => unreachable!("a mechanism this harness does not know"),
    }
}

fn len_ok(m: Mechanism, len: usize) -> bool {
    match m {
        Mechanism::MlKem512 | Mechanism::MlKem768 | Mechanism::MlKem1024 => len == 32,
        _ => len >= MIN_SECRET_LEN,
    }
}

// The body is a named function so that coverage tools report its lines (the macro hides them).
fuzz_target!(|data: &[u8]| check(data));

fn check(data: &[u8]) {
    let f = split(data);

    // Policy: up to 7 mechanisms, one byte each (duplicates allowed, to test refusal).
    let n = usize::from(f.selector % 8);
    let wanted: Vec<Mechanism> = f.a.iter().take(n).map(|b| ALL[usize::from(*b) % 5]).collect();
    let policy = Policy::new(&wanted);
    let dup = (0..wanted.len()).any(|i| wanted[..i].contains(&wanted[i]));
    match &policy {
        Ok(p) => {
            // An accepted policy is non-empty and names no mechanism twice: the documented rules
            // refuse both. Mutant: in `Policy::new`, `if mechanisms[..i].contains(m)` becomes
            // `if false && mechanisms[..i].contains(m)`; input `duplicate`.
            assert!(!wanted.is_empty() && !dup);
            // The policy keeps the mechanisms in the order given; the encoding depends on it.
            // Mutant: in `Policy::new`, `mechanisms.to_vec()` becomes
            // `mechanisms.iter().rev().copied().collect()`; input `qkd-mlkem768`.
            assert_eq!(p.mechanisms(), wanted.as_slice());
        }
        // `PolicySize` only for an empty policy (this target asks for at most 7 mechanisms).
        // Mutant: in `Policy::new`, `mechanisms.is_empty()` becomes `mechanisms.len() < 2`;
        // input `psk`.
        Err(CombinerError::PolicySize) => assert!(wanted.is_empty()),
        // `DuplicateMechanism` only when a mechanism appears twice. Mutant: in `Policy::new`,
        // `if mechanisms[..i].contains(m)` becomes `if i > 0`; input `qkd-mlkem768`.
        Err(CombinerError::DuplicateMechanism(_)) => assert!(dup),
        // `Policy::new` fails in no other way. Mutant: in `Policy::new`,
        // `Err(CombinerError::DuplicateMechanism(*m))` becomes
        // `Err(CombinerError::WrongCount { expected: i, got: 0 })`; input `duplicate`.
        Err(e) => panic!("unexpected policy error {e:?}"),
    }

    // Secrets: [mechanism byte][length byte][bytes], repeated.
    let mut secrets = Vec::new();
    let mut b = f.b;
    while b.len() >= 2 && secrets.len() < 8 {
        let m = ALL[usize::from(b[0]) % 5];
        let len = usize::from(b[1]).min(b.len() - 2);
        secrets.push(Secret::new(m, &b[2..2 + len]));
        b = &b[2 + len..];
    }
    let context = bounded(f.rest);

    if let Ok(p) = policy {
        let r = p.combine(&secrets, context);
        let valid = secrets.len() == wanted.len()
            && secrets
                .iter()
                .zip(&wanted)
                .all(|(s, m)| s.mechanism == *m && len_ok(s.mechanism, s.bytes.len()));
        // `combine` fails closed: it accepts exactly the secrets that match the policy one for
        // one, in order, with valid lengths (32 bytes for ML-KEM, at least MIN_SECRET_LEN for QKD
        // and pre-shared keys). Mutant: in `Mechanism::accepts_len`, `len >= MIN_SECRET_LEN`
        // becomes `len >= MIN_SECRET_LEN - 1`; input `short-secret`.
        assert_eq!(r.is_ok(), valid, "{r:?}");
        if let Ok(key) = r {
            let mut h = Sha3_256::new();
            h.update(COMBINER_LABEL);
            h.update([secrets.len() as u8]);
            for s in &secrets {
                h.update([id(s.mechanism)]);
                h.update((s.bytes.len() as u32).to_be_bytes());
                h.update(s.bytes);
            }
            h.update((context.len() as u32).to_be_bytes());
            h.update(context);
            // The key is SHA3-256 of the documented v1 encoding, recomputed above independently.
            // Mutant: in `Policy::combine`, `h.update([secrets.len() as u8])` becomes
            // `h.update([secrets.len() as u8 ^ 1])`; input `psk`.
            assert_eq!(key.as_slice(), h.finalize().as_slice());
            // Combining the same secrets again gives the same key. Mutant: in `Policy::combine`, a
            // static flag that adds `h.update(b"x")` from the second call on; input `psk`.
            assert_eq!(*key, *p.combine(&secrets, context).unwrap());
        }
    }

    // qkd_pqc_v2: any QKD key, a 32-byte PQC key.
    if f.b.len() >= 32 {
        let qkd = bounded(f.a);
        let pqc: [u8; 32] = f.b[..32].try_into().unwrap();
        let out = qkd_pqc_v2(qkd, &pqc);
        let mut h = Sha3_256::new();
        h.update(PQTG_MIXING_LABEL);
        h.update((qkd.len() as u32).to_be_bytes());
        h.update(qkd);
        h.update(pqc);
        // `qkd_pqc_v2` is SHA3-256 of its documented encoding. Mutant: in `qkd_pqc_v2`, the line
        // `h.update((qkd_key.len() as u32).to_be_bytes());` is removed; input `qkd-mlkem768`.
        assert_eq!(out.as_slice(), h.finalize().as_slice());
    }
}
