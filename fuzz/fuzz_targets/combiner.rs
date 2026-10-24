//! The combiner on arbitrary policies, secrets and contexts: `Policy::new` and `combine` never
//! panic, accept exactly what the documented rules accept, and `combine` returns SHA3-256 of the
//! documented v1 encoding, recomputed here. `qkd_pqc_v2` is checked the same way.
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
            assert!(!wanted.is_empty() && !dup);
            assert_eq!(p.mechanisms(), wanted.as_slice());
        }
        Err(CombinerError::PolicySize) => assert!(wanted.is_empty()),
        Err(CombinerError::DuplicateMechanism(_)) => assert!(dup),
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
            assert_eq!(key.as_slice(), h.finalize().as_slice());
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
        assert_eq!(out.as_slice(), h.finalize().as_slice());
    }
}
