//! `sign::verify` for SLH-DSA (SHAKE-128f, SHAKE-256s) on an arbitrary verification key,
//! signature and message (up to 1024 bytes, see fuzz/README.md): never panics, and accepts only
//! keys and signatures of the parameter set's exact lengths.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::sign::{self, SignAlgorithm, Signature, VerificationKey};
use paraxiom_pqc_fuzz::{bounded, split};

// The body is a named function so that coverage tools report its lines (the macro hides them).
fuzz_target!(|data: &[u8]| check(data));

fn check(data: &[u8]) {
    let f = split(data);
    let (alg, vk_len, sig_len) = match f.selector % 2 {
        0 => (SignAlgorithm::SlhDsaShake128f, 32, 17088),
        _ => (SignAlgorithm::SlhDsaShake256s, 64, 29792),
    };
    let vk = VerificationKey { algorithm: alg, bytes: f.a.to_vec() };
    let sig = Signature { algorithm: alg, bytes: f.b.to_vec() };
    if let Ok(true) = sign::verify(&vk, bounded(f.rest), &sig) {
        // Verification accepts only a key and a signature of the parameter set's exact lengths.
        // Mutant: in `sign::verify`, the SHAKE-128f arm returns `Ok(true)` instead of calling
        // `slh_dsa_verify`; input `selector-only` from `slh_dsa_verify_seed_corpus.zip`.
        assert_eq!((f.a.len(), f.b.len()), (vk_len, sig_len));
    }
}
