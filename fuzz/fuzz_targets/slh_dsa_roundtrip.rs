//! SLH-DSA-SHAKE-128f end to end, with the whole input as the message: a fresh key pair signs
//! it, the signature has the FIPS 205 length and verifies under the matching key, and signing
//! again gives the same bytes (this library signs SLH-DSA deterministically).
//!
//! Key generation reads the OS random source. If it fails, the run ends normally, so the property
//! reads: whenever key generation succeeds, the rest holds. Unforgeability is not asserted:
//! another message verifying is infeasible, not impossible, so it does not hold on every input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::sign::{self, SignAlgorithm};

fuzz_target!(|msg: &[u8]| {
    let alg = SignAlgorithm::SlhDsaShake128f;
    let Ok(kp) = sign::keypair(alg) else {
        return;
    };
    let sig = sign::sign(&kp.sk, msg).expect("signing with a fresh key failed");
    assert_eq!((sig.algorithm, sig.bytes.len()), (alg, 17088));
    assert_eq!(sign::verify(&kp.vk, msg, &sig).ok(), Some(true), "a fresh signature does not verify");
    let again = sign::sign(&kp.sk, msg).expect("signing twice failed");
    assert_eq!(again.bytes, sig.bytes, "SLH-DSA signing is not deterministic");
});
