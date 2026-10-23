//! SLH-DSA-SHAKE-128f end to end, with the whole input as the message: a fresh key pair signs
//! it, the signature has the FIPS 205 length and verifies under the matching key, and signing
//! again gives the same bytes (this library signs SLH-DSA deterministically).
//!
//! Unforgeability is not asserted: another message verifying is infeasible, not impossible, so
//! it is not a statement that holds on every input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::sign::{self, SignAlgorithm};

fuzz_target!(|msg: &[u8]| {
    let alg = SignAlgorithm::SlhDsaShake128f;
    let kp = sign::keypair(alg).expect("SLH-DSA key generation failed");
    let sig = sign::sign(&kp.sk, msg).expect("signing with a fresh key failed");
    assert_eq!((sig.algorithm, sig.bytes.len()), (alg, 17088));
    assert_eq!(sign::verify(&kp.vk, msg, &sig).ok(), Some(true), "a fresh signature does not verify");
    let again = sign::sign(&kp.sk, msg).expect("signing twice failed");
    assert_eq!(again.bytes, sig.bytes, "SLH-DSA signing is not deterministic");
});
