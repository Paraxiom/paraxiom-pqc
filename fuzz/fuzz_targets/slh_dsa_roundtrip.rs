//! SLH-DSA-SHAKE-128f end to end, with every random value taken from the input, as OSS Verify asks
//! (no OS random source): the first 48 bytes are SK.seed, SK.prf and PK.seed, 16 bytes each and zero
//! padded when the input is shorter, and the next 1024 bytes at most are the message. The key
//! pair comes from FIPS 205 key generation (`slh_keygen_internal` of the vendored crate). The
//! library then signs: the signature has the FIPS 205 length and verifies under the matching key,
//! and signing again gives the same bytes.
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
    // FIPS 205 key generation gives a 64-byte signing key and a 32-byte verification key for
    // SHAKE-128f. Mutant (in this file): `raw.to_bytes().to_vec()` becomes
    // `raw.to_bytes()[1..].to_vec()`; input `zero-seeds` from `slh_dsa_roundtrip_seed_corpus.zip`.
    assert_eq!((sk.bytes.len(), vk.bytes.len()), (64, 32));

    // Signing with a well-formed key succeeds. Mutant: in `slh_dsa_sign`, the context `b""`
    // becomes `&[0u8; 256]`, which FIPS 205 refuses; input `zero-seeds`.
    let sig = sign::sign(&sk, msg).expect("signing with a well-formed key failed");
    // The signature has its algorithm and the FIPS 205 length. Mutant: in `slh_dsa_sign`,
    // `bytes: sig.to_vec()` becomes `bytes: sig.to_vec()[1..].to_vec()`; input `zero-seeds`.
    assert_eq!((sig.algorithm, sig.bytes.len()), (alg, 17088));
    // A fresh signature verifies under the matching key. Mutant: in `slh_dsa_verify`, the context
    // `b""` becomes `b"x"`; input `zero-seeds`.
    assert_eq!(sign::verify(&vk, msg, &sig).ok(), Some(true), "a fresh signature does not verify");
    // Signing a second time succeeds. Mutant: in `slh_dsa_sign`, a static flag that returns an
    // error from the second call on; input `zero-seeds`.
    let again = sign::sign(&sk, msg).expect("signing twice failed");
    // Signing twice gives the same bytes: the library signs SLH-DSA deterministically. Mutant: in
    // `slh_dsa_sign`, `None` becomes 16 random bytes from `getrandom` (hedged signing); input
    // `zero-seeds`.
    assert_eq!(again.bytes, sig.bytes, "SLH-DSA signing is not deterministic");
}
