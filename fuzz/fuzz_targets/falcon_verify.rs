//! Falcon verification on an arbitrary public key, signature and message: neither
//! `falcon::verify` nor `sign::verify` panics; `falcon::verify` accepts only Falcon-512 and
//! Falcon-1024 keys (header 0x09 with 897 bytes, header 0x0A with 1793 bytes); and
//! `sign::verify` agrees with it when the key's degree matches the label and refuses otherwise.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::falcon;
use paraxiom_pqc::sign::{self, SignAlgorithm, Signature, VerificationKey};
use paraxiom_pqc_fuzz::split;

fuzz_target!(|data: &[u8]| {
    let f = split(data);
    let (alg, header) = if f.selector % 2 == 0 {
        (SignAlgorithm::Falcon512, 0x09)
    } else {
        (SignAlgorithm::Falcon1024, 0x0A)
    };
    let direct = falcon::verify(f.a, f.rest, f.b);
    if direct {
        assert!(matches!(
            (f.a.first(), f.a.len()),
            (Some(0x09), 897) | (Some(0x0A), 1793)
        ));
    }
    let vk = VerificationKey { algorithm: alg, bytes: f.a.to_vec() };
    let sig = Signature { algorithm: alg, bytes: f.b.to_vec() };
    let via_sign = sign::verify(&vk, f.rest, &sig);
    assert_eq!(via_sign.ok(), Some(direct && f.a.first() == Some(&header)));
});
