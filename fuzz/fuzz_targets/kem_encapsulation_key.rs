//! `kem::encapsulate` on an arbitrary encapsulation key: never panics, and succeeds exactly when
//! the key passes the FIPS 203 section 7.2 check (right length, every coefficient below q),
//! checked by an independent decoder.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::kem::{self, EncapsulationKey, KemAlgorithm};
use paraxiom_pqc_fuzz::{ek_is_valid, split};

fuzz_target!(|data: &[u8]| {
    let f = split(data);
    let (alg, k, ct_len) = match f.selector % 3 {
        0 => (KemAlgorithm::MlKem512, 2, 768),
        1 => (KemAlgorithm::MlKem768, 3, 1088),
        _ => (KemAlgorithm::MlKem1024, 4, 1568),
    };
    let ek = EncapsulationKey { algorithm: alg, bytes: f.a.to_vec() };
    let r = kem::encapsulate(&ek);
    assert_eq!(r.is_ok(), ek_is_valid(k, f.a), "acceptance differs from FIPS 203 7.2");
    if let Ok((ct, ss)) = r {
        assert_eq!((ct.bytes.len(), ss.bytes.len()), (ct_len, 32));
        assert_eq!(ct.algorithm, alg);
    }
});
