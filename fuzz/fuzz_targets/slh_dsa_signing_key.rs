//! SLH-DSA alone, so that its signing path can stand as a proof target without the ML-DSA and
//! Falcon paths of `signing_key`: any byte string as a signing key, any message. A key of the
//! wrong length is refused; a signature that comes out has the algorithm and the FIPS 205
//! length of its parameter set. SLH-DSA-SHAKE-256s signs slowly, so it gets one input in eight.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::sign::{self, SignAlgorithm, SigningKey};
use paraxiom_pqc_fuzz::{bounded, split};

// The body is a named function so that coverage tools report its lines (the macro hides them).
fuzz_target!(|data: &[u8]| check(data));

fn check(data: &[u8]) {
    let f = split(data);
    let (alg, sk_len, sig_len) = if f.selector % 8 == 7 {
        (SignAlgorithm::SlhDsaShake256s, 128, 29792)
    } else {
        (SignAlgorithm::SlhDsaShake128f, 64, 17088)
    };
    let sk = SigningKey { algorithm: alg, bytes: f.a.to_vec() };
    let signed = sign::sign(&sk, bounded(f.rest));
    if f.a.len() != sk_len {
        assert!(signed.is_err(), "a signing key of the wrong length was accepted");
    }
    if let Ok(sig) = signed {
        assert_eq!((sig.algorithm, sig.bytes.len()), (alg, sig_len));
    }
}
