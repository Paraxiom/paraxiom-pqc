//! SLH-DSA-SHAKE-128f end to end, with every random value taken from the input, as OSS Verify asks
//! (no OS random source): the first 48 bytes are SK.seed, SK.prf and PK.seed, 16 bytes each and zero
//! padded when the input is shorter, and the rest is the message. The key pair comes from FIPS 205
//! key generation (`slh_keygen_internal` of the vendored crate). The library then signs: the
//! signature has the FIPS 205 length and verifies under the matching key, and signing again gives
//! the same bytes.
//!
//! Unforgeability is not asserted: another message verifying is infeasible, not impossible, so it
//! does not hold on every input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paraxiom_pqc::sign::{self, SignAlgorithm, SigningKey, VerificationKey};
use paraxiom_pqc_fuzz::bounded;
use slh_dsa::{Shake128f, VerifyingKey};

const N: usize = 16;

// The body is a named function so that coverage tools report its lines (the macro hides them).
fuzz_target!(|data: &[u8]| check(data));

fn check(data: &[u8]) {
    let mut seeds = [0u8; 3 * N];
    let taken = data.len().min(3 * N);
    seeds[..taken].copy_from_slice(&data[..taken]);
    let msg = bounded(&data[taken..]);
    let (sk_seed, rest) = seeds.split_at(N);
    let (sk_prf, pk_seed) = rest.split_at(N);

    let raw = slh_dsa::SigningKey::<Shake128f>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
    let raw_vk: &VerifyingKey<Shake128f> = raw.as_ref();
    let alg = SignAlgorithm::SlhDsaShake128f;
    let sk = SigningKey { algorithm: alg, bytes: raw.to_bytes().to_vec() };
    let vk = VerificationKey { algorithm: alg, bytes: raw_vk.to_bytes().to_vec() };
    assert_eq!((sk.bytes.len(), vk.bytes.len()), (64, 32));

    let sig = sign::sign(&sk, msg).expect("signing with a well-formed key failed");
    assert_eq!((sig.algorithm, sig.bytes.len()), (alg, 17088));
    assert_eq!(sign::verify(&vk, msg, &sig).ok(), Some(true), "a fresh signature does not verify");
    let again = sign::sign(&sk, msg).expect("signing twice failed");
    assert_eq!(again.bytes, sig.bytes, "SLH-DSA signing is not deterministic");
}
