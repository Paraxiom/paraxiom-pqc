//! Writes a seed corpus of valid inputs (real keys, ciphertexts and signatures) for each fuzz
//! target into `corpus/<target>/`, so that fuzzing starts deep inside the parsers instead of at
//! the length checks. Run with `cargo run --bin gen_corpus` from `fuzz/`.

use paraxiom_pqc::combiner::Mechanism;
use paraxiom_pqc::kem::{self, KemAlgorithm};
use paraxiom_pqc::sign::{self, SignAlgorithm};
use paraxiom_pqc_fuzz::join;
use std::fs;

fn write(target: &str, name: &str, data: &[u8]) {
    let dir = format!("corpus/{target}");
    fs::create_dir_all(&dir).unwrap();
    fs::write(format!("{dir}/{name}"), data).unwrap();
}

fn main() {
    for (sel, alg) in [KemAlgorithm::MlKem512, KemAlgorithm::MlKem768, KemAlgorithm::MlKem1024]
        .into_iter()
        .enumerate()
    {
        let sel = sel as u8;
        let kp = kem::keypair(alg).unwrap();
        let (ct, _) = kem::encapsulate(&kp.ek).unwrap();
        write("kem_encapsulation_key", &format!("valid-{sel}"), &join(sel, &kp.ek.bytes, b"", b""));
        let mut bad = kp.ek.bytes.clone();
        bad[0] = 0xff;
        bad[1] |= 0x0f; // first coefficient 4095 >= q
        write("kem_encapsulation_key", &format!("over-q-{sel}"), &join(sel, &bad, b"", b""));
        write("kem_decapsulate", &format!("valid-{sel}"), &join(sel, &kp.dk.bytes, &ct.bytes, b""));
        let mut modified = ct.bytes.clone();
        modified[3] ^= 0x40;
        write("kem_decapsulate", &format!("modified-{sel}"), &join(sel, &kp.dk.bytes, &modified, b""));
    }

    let msg = b"paraxiom-pqc fuzz seed";
    let sign_seed = |target: &str, sel: u8, alg: SignAlgorithm| {
        let kp = sign::keypair(alg).unwrap();
        let sig = sign::sign(&kp.sk, msg).unwrap();
        write(target, &format!("valid-{sel}"), &join(sel, &kp.vk.bytes, &sig.bytes, msg));
        kp
    };
    for (sel, alg) in [SignAlgorithm::MlDsa44, SignAlgorithm::MlDsa65, SignAlgorithm::MlDsa87]
        .into_iter()
        .enumerate()
    {
        let kp = sign_seed("ml_dsa_verify", sel as u8, alg);
        write("signing_key", &format!("ml-dsa-{sel}"), &join(sel as u8, &kp.sk.bytes, b"", msg));
    }
    let kp = sign_seed("slh_dsa_verify", 0, SignAlgorithm::SlhDsaShake128f);
    write("signing_key", "slh-dsa-128f", &join(3, &kp.sk.bytes, b"", msg));
    write("slh_dsa_signing_key", "valid-128f", &join(0, &kp.sk.bytes, b"", msg));
    let kp = sign_seed("slh_dsa_verify", 1, SignAlgorithm::SlhDsaShake256s);
    write("slh_dsa_signing_key", "valid-256s", &join(7, &kp.sk.bytes, b"", msg));
    write("slh_dsa_roundtrip", "empty", b"");
    write("slh_dsa_roundtrip", "message", msg);
    if sign::FALCON_SIGNING_AVAILABLE {
        let kp = sign_seed("falcon_verify", 0, SignAlgorithm::Falcon512);
        write("signing_key", "falcon-512", &join(4, &kp.sk.bytes, b"", msg));
        let kp = sign_seed("falcon_verify", 1, SignAlgorithm::Falcon1024);
        write("signing_key", "falcon-1024", &join(5, &kp.sk.bytes, b"", msg));
    }

    // Combiner: policy QKD + ML-KEM-768, matching secrets, a context.
    let mech = |m: Mechanism| match m {
        Mechanism::Qkd => 0u8,
        Mechanism::MlKem512 => 1,
        Mechanism::MlKem768 => 2,
        Mechanism::MlKem1024 => 3,
        _ => 4,
    };
    let policy = [mech(Mechanism::Qkd), mech(Mechanism::MlKem768)];
    let mut secrets = vec![mech(Mechanism::Qkd), 32];
    secrets.extend_from_slice(&[0x80; 32]);
    secrets.extend_from_slice(&[mech(Mechanism::MlKem768), 32]);
    secrets.extend_from_slice(&[0x40; 32]);
    write("combiner", "qkd-mlkem768", &join(2, &policy, &secrets, b"transcript"));
    let policy = [mech(Mechanism::PreShared)];
    let mut secrets = vec![mech(Mechanism::PreShared), 16];
    secrets.extend_from_slice(&[0x11; 16]);
    write("combiner", "psk", &join(1, &policy, &secrets, b""));
    println!("corpus written");
}
