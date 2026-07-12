//! QRNG-seeded key generation (feature `qrng`). Proves the pipeline end-to-end:
//! quantum entropy source → SHAKE256-conditioned CSPRNG → real ML-DSA keypair
//! that signs and verifies.
#![cfg(feature = "qrng")]

use paraxiom_pqc::qrng::{QrngRng, TestQuantumSource};
use paraxiom_pqc::sign::{self, SignAlgorithm};

#[test]
fn qrng_seeds_a_working_ml_dsa_keypair() {
    let mut rng = QrngRng::new(TestQuantumSource::seeded(0xC0FFEE)).unwrap();
    let kp = sign::keypair_qrng(SignAlgorithm::MlDsa65, &mut rng).unwrap();

    let msg = b"quantum-seeded signature";
    let sig = sign::sign(&kp.sk, msg).unwrap();
    assert!(
        sign::verify(&kp.vk, msg, &sig).unwrap(),
        "QRNG-seeded ML-DSA keypair must sign and verify"
    );
}

#[test]
fn qrng_pipeline_is_deterministic_in_the_source_seed() {
    let gen = |seed: u64| {
        let mut rng = QrngRng::new(TestQuantumSource::seeded(seed)).unwrap();
        sign::keypair_qrng(SignAlgorithm::MlDsa65, &mut rng)
            .unwrap()
            .sk
            .bytes
    };
    // Same quantum seed → same conditioned key material → same keypair.
    assert_eq!(gen(42), gen(42), "same source seed must yield the same key");
    // Different seed → different key (the conditioner propagates entropy).
    assert_ne!(
        gen(42),
        gen(99),
        "different source seed must yield a different key"
    );
}

#[test]
fn qrng_keygen_unsupported_alg_errors_cleanly() {
    let mut rng = QrngRng::new(TestQuantumSource::seeded(1)).unwrap();
    // SLH-DSA / Falcon aren't wired to the QRNG yet — must fail explicitly,
    // not silently fall back to the OS RNG.
    assert!(sign::keypair_qrng(SignAlgorithm::SlhDsaShake128f, &mut rng).is_err());
    assert!(sign::keypair_qrng(SignAlgorithm::Falcon512, &mut rng).is_err());
}
