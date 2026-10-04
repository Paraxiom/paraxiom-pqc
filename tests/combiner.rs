#![cfg(feature = "combiner")]

use paraxiom_pqc::combiner::{qkd_pqc_v2, CombinerError, Mechanism, Policy, Secret};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn seq(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

// Cross-implementation vectors from pq-transport-gateway tests/vectors/handshake-v2.json.
#[test]
fn qkd_pqc_v2_matches_pqtg_mix_keys_256() {
    let kem: [u8; 32] = seq(0x40, 32).try_into().unwrap();
    let out = qkd_pqc_v2(&seq(0x80, 32), &kem);
    assert_eq!(hex(&*out), "8f2b82f7599ea0e560395b1f4504172403d295124eb8ab913c2312e2b7270eff");
}

#[test]
fn qkd_pqc_v2_matches_pqtg_mix_keys_512() {
    let kem: [u8; 32] = seq(0x40, 32).try_into().unwrap();
    let out = qkd_pqc_v2(&seq(0xc0, 64), &kem);
    assert_eq!(hex(&*out), "030640350c85b4e610dc61ef14601a15ed1b0e5a1cd0f4a64f56df3e3772d77c");
}

fn qkd_mlkem768() -> Policy {
    Policy::new(&[Mechanism::Qkd, Mechanism::MlKem768]).unwrap()
}

#[test]
fn combine_v1_fixed_vector() {
    // Guards the v1 encoding against accidental change.
    let (qkd, kem) = (seq(0x80, 32), seq(0x40, 32));
    let out = qkd_mlkem768()
        .combine(&[Secret::new(Mechanism::Qkd, &qkd), Secret::new(Mechanism::MlKem768, &kem)], b"transcript")
        .unwrap();
    assert_eq!(hex(&*out), COMBINE_V1_VECTOR);
}

// Computed independently from the encoding spec with Python hashlib.sha3_256, not taken
// from this implementation.
const COMBINE_V1_VECTOR: &str = "370221adc59478bb4f81208440845a588a91ab3a426c388bc5dc2a7fc4f69b57";

#[test]
fn every_input_changes_the_output() {
    let (qkd, kem) = (seq(0x80, 32), seq(0x40, 32));
    let base = qkd_mlkem768()
        .combine(&[Secret::new(Mechanism::Qkd, &qkd), Secret::new(Mechanism::MlKem768, &kem)], b"ctx")
        .unwrap();
    let mut q2 = qkd.clone();
    q2[31] ^= 1;
    let mut k2 = kem.clone();
    k2[0] ^= 1;
    for (q, k, c) in [(&q2, &kem, &b"ctx"[..]), (&qkd, &k2, &b"ctx"[..]), (&qkd, &kem, &b"ctX"[..])] {
        let other = qkd_mlkem768()
            .combine(&[Secret::new(Mechanism::Qkd, q), Secret::new(Mechanism::MlKem768, k)], c)
            .unwrap();
        assert_ne!(*base, *other);
    }
}

#[test]
fn mechanism_is_bound_into_the_key() {
    let kem = seq(0x40, 32);
    let a = Policy::new(&[Mechanism::MlKem768]).unwrap().combine(&[Secret::new(Mechanism::MlKem768, &kem)], b"").unwrap();
    let b = Policy::new(&[Mechanism::MlKem1024]).unwrap().combine(&[Secret::new(Mechanism::MlKem1024, &kem)], b"").unwrap();
    assert_ne!(*a, *b);
}

#[test]
fn length_prefix_separates_boundaries() {
    // Same concatenated bytes, split differently between QKD key and pre-shared key.
    let all = seq(0x01, 48);
    let p = Policy::new(&[Mechanism::Qkd, Mechanism::PreShared]).unwrap();
    let a = p.combine(&[Secret::new(Mechanism::Qkd, &all[..16]), Secret::new(Mechanism::PreShared, &all[16..])], b"").unwrap();
    let b = p.combine(&[Secret::new(Mechanism::Qkd, &all[..32]), Secret::new(Mechanism::PreShared, &all[32..])], b"").unwrap();
    assert_ne!(*a, *b);
}

#[test]
fn missing_qkd_key_fails_closed() {
    let kem = seq(0x40, 32);
    let err = qkd_mlkem768().combine(&[Secret::new(Mechanism::MlKem768, &kem)], b"").unwrap_err();
    assert_eq!(err, CombinerError::WrongCount { expected: 2, got: 1 });
}

#[test]
fn wrong_order_or_mechanism_is_refused() {
    let (qkd, kem) = (seq(0x80, 32), seq(0x40, 32));
    let err = qkd_mlkem768()
        .combine(&[Secret::new(Mechanism::MlKem768, &kem), Secret::new(Mechanism::Qkd, &qkd)], b"")
        .unwrap_err();
    assert!(matches!(err, CombinerError::WrongMechanism { index: 0, .. }));
}

#[test]
fn bad_lengths_are_refused() {
    let p = qkd_mlkem768();
    let short_qkd = seq(0x80, 8);
    let kem = seq(0x40, 32);
    assert!(matches!(
        p.combine(&[Secret::new(Mechanism::Qkd, &short_qkd), Secret::new(Mechanism::MlKem768, &kem)], b""),
        Err(CombinerError::BadLength { index: 0, .. })
    ));
    let qkd = seq(0x80, 32);
    let kem31 = seq(0x40, 31);
    assert!(matches!(
        p.combine(&[Secret::new(Mechanism::Qkd, &qkd), Secret::new(Mechanism::MlKem768, &kem31)], b""),
        Err(CombinerError::BadLength { index: 1, .. })
    ));
}

#[test]
fn policies_are_validated() {
    assert_eq!(Policy::new(&[]).unwrap_err(), CombinerError::PolicySize);
    assert_eq!(
        Policy::new(&[Mechanism::Qkd, Mechanism::Qkd]).unwrap_err(),
        CombinerError::DuplicateMechanism(Mechanism::Qkd)
    );
}
