//! `kem::decapsulate` on an arbitrary decapsulation key (seed) and ciphertext: never panics,
//! and succeeds exactly when the seed is 64 bytes and the ciphertext has the set's length
//! (any such ciphertext decapsulates, to the real key or to the implicit-rejection key).
#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::kem::{self, Ciphertext, DecapsulationKey, KemAlgorithm};
use paraxiom_pqc_fuzz::split;

fuzz_target!(|data: &[u8]| {
    let f = split(data);
    let (alg, ct_len) = match f.selector % 3 {
        0 => (KemAlgorithm::MlKem512, 768),
        1 => (KemAlgorithm::MlKem768, 1088),
        _ => (KemAlgorithm::MlKem1024, 1568),
    };
    // The ciphertext's own label is ignored by decapsulate; vary it anyway.
    let ct_alg = match (f.selector / 3) % 3 {
        0 => KemAlgorithm::MlKem512,
        1 => KemAlgorithm::MlKem768,
        _ => KemAlgorithm::MlKem1024,
    };
    let dk = DecapsulationKey { algorithm: alg, bytes: f.a.to_vec() };
    let ct = Ciphertext { algorithm: ct_alg, bytes: f.b.to_vec() };
    let r = kem::decapsulate(&dk, &ct);
    assert_eq!(r.is_ok(), f.a.len() == 64 && f.b.len() == ct_len);
    if let Ok(ss) = r {
        assert_eq!(ss.bytes.len(), 32);
    }
});
