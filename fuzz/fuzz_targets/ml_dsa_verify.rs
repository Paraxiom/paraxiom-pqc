//! `sign::verify` for ML-DSA on an arbitrary verification key, signature and message: never
//! panics, and accepts only keys and signatures of the parameter set's exact lengths.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::sign::{self, SignAlgorithm, Signature, VerificationKey};
use paraxiom_pqc_fuzz::split;

fuzz_target!(|data: &[u8]| {
    let f = split(data);
    let (alg, vk_len, sig_len) = match f.selector % 3 {
        0 => (SignAlgorithm::MlDsa44, 1312, 2420),
        1 => (SignAlgorithm::MlDsa65, 1952, 3309),
        _ => (SignAlgorithm::MlDsa87, 2592, 4627),
    };
    let vk = VerificationKey { algorithm: alg, bytes: f.a.to_vec() };
    let sig = Signature { algorithm: alg, bytes: f.b.to_vec() };
    if let Ok(true) = sign::verify(&vk, f.rest, &sig) {
        assert_eq!((f.a.len(), f.b.len()), (vk_len, sig_len));
    }
});
