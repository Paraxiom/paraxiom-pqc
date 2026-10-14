//! QRNG-seeded key generation (feature `qrng`). Proves the pipeline end-to-end:
//! quantum entropy source → SHAKE256-conditioned CSPRNG → real ML-DSA keypair
//! that signs and verifies.
#![cfg(all(feature = "qrng", feature = "sign"))]

use paraxiom_pqc::qrng::{QrngRng, QuantumSource};
use paraxiom_pqc::sign::{self, SignAlgorithm};
use paraxiom_pqc::PqcError;

/// Deterministic stand-in for a quantum source (seeded xorshift64), for these tests only.
/// It is not cryptographic and is deliberately kept out of the library so that no build can
/// use it as an entropy source; it only lets the tests run the conditioning pipeline
/// reproducibly.
struct TestQuantumSource {
    state: u64,
}

impl TestQuantumSource {
    fn seeded(seed: u64) -> Self {
        Self {
            state: seed | 1, // avoid the zero fixed point
        }
    }
}

impl QuantumSource for TestQuantumSource {
    fn fill_entropy(&mut self, dest: &mut [u8]) -> Result<(), PqcError> {
        for chunk in dest.chunks_mut(8) {
            // xorshift64
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            let bytes = x.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

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
        // SigningKey clears itself on drop, so its bytes are cloned rather than moved out.
        sign::keypair_qrng(SignAlgorithm::MlDsa65, &mut rng)
            .unwrap()
            .sk
            .bytes
            .clone()
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
