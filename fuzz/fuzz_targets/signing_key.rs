//! Signing-key parsing: `sign::sign`, `sign::sign_randomized` and
//! `sign::sign_deterministic_dangerous` (chosen by the selector) with arbitrary key bytes never
//! panic, and succeed only for keys of the scheme's exact length (for Falcon, also with the
//! header of the labelled degree, and only where Falcon signing is built).
//! SLH-DSA-SHAKE-256s is left out to keep the execution rate up: its parsing is the same
//! generic code as SHAKE-128f's, and each signature takes a large fraction of a second.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::sign::{self, SignAlgorithm, SigningKey};
use paraxiom_pqc_fuzz::split;

fuzz_target!(|data: &[u8]| {
    let f = split(data);
    let (alg, len) = match f.selector % 6 {
        0 => (SignAlgorithm::MlDsa44, 32),
        1 => (SignAlgorithm::MlDsa65, 32),
        2 => (SignAlgorithm::MlDsa87, 32),
        3 => (SignAlgorithm::SlhDsaShake128f, 64),
        4 => (SignAlgorithm::Falcon512, 1281),
        _ => (SignAlgorithm::Falcon1024, 2305),
    };
    let sk = SigningKey { algorithm: alg, bytes: f.a.to_vec() };
    let signed = match (f.selector / 6) % 3 {
        0 => sign::sign(&sk, f.rest),
        1 => sign::sign_randomized(&sk, f.rest),
        _ => sign::sign_deterministic_dangerous(&sk, f.rest),
    };
    if let Ok(sig) = signed {
        assert_eq!(f.a.len(), len);
        assert_eq!(sig.algorithm, alg);
        if matches!(alg, SignAlgorithm::Falcon512 | SignAlgorithm::Falcon1024) {
            assert!(sign::FALCON_SIGNING_AVAILABLE);
            let header = if alg == SignAlgorithm::Falcon512 { 0x59 } else { 0x5A };
            assert_eq!(f.a[0], header);
        }
    }
});
