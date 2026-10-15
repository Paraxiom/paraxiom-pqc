//! Property tests (proptest) for the public API.
//!
//! Case counts are kept small so that `cargo test` stays quick in debug builds; set
//! `PROPTEST_CASES` to run more (every property here then runs that many cases).
//!
//! KEM: round trips at every parameter set, from generated keys and from arbitrary seeds; any
//! modified or arbitrary ciphertext decapsulates to the implicit-rejection key J(z || c) of
//! FIPS 203 (computed here with sha3, independently of ml-kem), never to the real secret and
//! never with a panic; a ciphertext decapsulated with another seed gives that seed's J(z' || c);
//! wrong lengths are errors; and `encapsulate` accepts an encapsulation key
//! exactly when every coefficient is below q (FIPS 203 section 7.2, checked by an independent
//! decoder here).
//!
//! Signatures, for every scheme built on this host: round trips through all three signing
//! functions; a flipped bit in the signature, the message or the verification key is never
//! accepted; a signature is refused under another valid key of the same scheme and under
//! another scheme's label (Falcon-512 and Falcon-1024 included); encodings round-trip through the backends; the fixed-round ML-DSA kernel returns
//! the same signature as deterministic ML-DSA.Sign; malformed keys and signatures give errors,
//! not panics, and signing keys of the right length with arbitrary contents do not panic.

use paraxiom_pqc::kem::{self, Ciphertext, DecapsulationKey, EncapsulationKey, KemAlgorithm};
use proptest::prelude::*;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// `default` cases unless `PROPTEST_CASES` is set.
fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn config(default: u32) -> ProptestConfig {
    ProptestConfig {
        cases: cases(default),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

// ── ML-KEM ──────────────────────────────────────────────────────────────────

const KEM_ALGS: [KemAlgorithm; 3] = [
    KemAlgorithm::MlKem512,
    KemAlgorithm::MlKem768,
    KemAlgorithm::MlKem1024,
];

fn kem_alg() -> impl Strategy<Value = KemAlgorithm> {
    prop::sample::select(KEM_ALGS.to_vec())
}

/// (k, encapsulation key length, ciphertext length) from FIPS 203 Table 3.
fn kem_sizes(alg: KemAlgorithm) -> (usize, usize, usize) {
    match alg {
        KemAlgorithm::MlKem512 => (2, 800, 768),
        KemAlgorithm::MlKem768 => (3, 1184, 1088),
        KemAlgorithm::MlKem1024 => (4, 1568, 1568),
    }
}

/// The encapsulation key for a seed, computed the way `kem::keypair` does.
fn ek_from_seed(alg: KemAlgorithm, seed: &[u8; 64]) -> Vec<u8> {
    use ml_kem::{KeyExport, KeyInit};
    let seed = ml_kem::Seed::from(*seed);
    match alg {
        KemAlgorithm::MlKem512 => ml_kem::DecapsulationKey::<ml_kem::MlKem512>::new(&seed)
            .encapsulation_key()
            .to_bytes()
            .to_vec(),
        KemAlgorithm::MlKem768 => ml_kem::DecapsulationKey::<ml_kem::MlKem768>::new(&seed)
            .encapsulation_key()
            .to_bytes()
            .to_vec(),
        KemAlgorithm::MlKem1024 => ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::new(&seed)
            .encapsulation_key()
            .to_bytes()
            .to_vec(),
    }
}

/// FIPS 203 Algorithm 18 line 7: K' = J(z || c) = SHAKE256(z || c, 256 bits).
fn implicit_rejection_key(z: &[u8], c: &[u8]) -> Vec<u8> {
    let mut h = sha3::Shake256::default();
    h.update(z);
    h.update(c);
    let mut out = vec![0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

/// ByteEncode_12 (FIPS 203 Algorithm 5) of 256 * k coefficients, followed by rho.
fn encode_ek(coeffs: &[u16], rho: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(coeffs.len() * 3 / 2 + 32);
    for pair in coeffs.chunks(2) {
        let (a, b) = (pair[0], pair[1]);
        out.push(a as u8);
        out.push(((a >> 8) as u8) | ((b as u8 & 0x0f) << 4));
        out.push((b >> 4) as u8);
    }
    out.extend_from_slice(rho);
    out
}

fn kem_pair(alg: KemAlgorithm, seed: [u8; 64]) -> (EncapsulationKey, DecapsulationKey) {
    let ek = EncapsulationKey {
        algorithm: alg,
        bytes: ek_from_seed(alg, &seed),
    };
    let dk = DecapsulationKey {
        algorithm: alg,
        bytes: seed.to_vec(),
    };
    (ek, dk)
}

proptest! {
    #![proptest_config(config(24))]

    /// Any 64-byte seed is a working decapsulation key, paired with the encapsulation key
    /// `kem::keypair` would derive from it.
    #[test]
    fn kem_round_trip_from_any_seed(alg in kem_alg(), seed in any::<[u8; 64]>()) {
        let (k, ek_len, ct_len) = kem_sizes(alg);
        let (ek, dk) = kem_pair(alg, seed);
        prop_assert_eq!(ek.bytes.len(), ek_len);
        prop_assert_eq!(ek.bytes.len(), 384 * k + 32);
        let (ct, ss) = kem::encapsulate(&ek).unwrap();
        prop_assert_eq!((ct.bytes.len(), ss.bytes.len()), (ct_len, 32));
        prop_assert_eq!(&kem::decapsulate(&dk, &ct).unwrap().bytes, &ss.bytes);
    }

    /// Generated key pairs: the seed is 64 bytes, the encapsulation key is the one the seed
    /// derives, and the pair round-trips. Each encapsulation is fresh.
    #[test]
    fn kem_round_trip_with_generated_keys(alg in kem_alg()) {
        let kp = kem::keypair(alg).unwrap();
        prop_assert_eq!(kp.dk.bytes.len(), 64);
        prop_assert_eq!(kp.ek.algorithm, alg);
        prop_assert_eq!(kp.dk.algorithm, alg);
        let seed: [u8; 64] = kp.dk.bytes.as_slice().try_into().unwrap();
        prop_assert_eq!(&kp.ek.bytes, &ek_from_seed(alg, &seed));
        let (ct1, ss1) = kem::encapsulate(&kp.ek).unwrap();
        let (ct2, ss2) = kem::encapsulate(&kp.ek).unwrap();
        prop_assert_ne!(&ct1.bytes, &ct2.bytes);
        prop_assert_ne!(&ss1.bytes, &ss2.bytes);
        prop_assert_eq!(&kem::decapsulate(&kp.dk, &ct1).unwrap().bytes, &ss1.bytes);
        prop_assert_eq!(&kem::decapsulate(&kp.dk, &ct2).unwrap().bytes, &ss2.bytes);
    }

    /// Implicit rejection: a ciphertext with any byte changed decapsulates, without an error
    /// or a panic, to J(z || c'), which is not the encapsulated secret.
    #[test]
    fn kem_modified_ciphertext_gives_implicit_rejection_key(
        alg in kem_alg(),
        seed in any::<[u8; 64]>(),
        index in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let (ek, dk) = kem_pair(alg, seed);
        let (ct, ss) = kem::encapsulate(&ek).unwrap();
        let mut bad = ct.bytes.clone();
        let i = index.index(bad.len());
        bad[i] ^= flip;
        let got = kem::decapsulate(&dk, &Ciphertext { algorithm: alg, bytes: bad.clone() }).unwrap();
        prop_assert_eq!(&got.bytes, &implicit_rejection_key(&seed[32..], &bad));
        prop_assert_ne!(&got.bytes, &ss.bytes);
    }

    /// A ciphertext of the right length that no one encapsulated decapsulates to J(z || c).
    #[test]
    fn kem_arbitrary_ciphertext_gives_implicit_rejection_key(
        alg in kem_alg(),
        seed in any::<[u8; 64]>(),
        noise in prop::collection::vec(any::<u8>(), 1568),
    ) {
        let (_, _, ct_len) = kem_sizes(alg);
        let c = noise[..ct_len].to_vec();
        let dk = DecapsulationKey { algorithm: alg, bytes: seed.to_vec() };
        let got = kem::decapsulate(&dk, &Ciphertext { algorithm: alg, bytes: c.clone() }).unwrap();
        prop_assert_eq!(&got.bytes, &implicit_rejection_key(&seed[32..], &c));
    }

    /// Wrong lengths are errors, never panics: decapsulation key, ciphertext, encapsulation key.
    #[test]
    fn kem_wrong_lengths_are_errors(
        alg in kem_alg(),
        bytes in prop::collection::vec(any::<u8>(), 0..1700),
    ) {
        let (_, ek_len, ct_len) = kem_sizes(alg);
        let good_seed = [7u8; 64];
        let good_ct = vec![0u8; ct_len];
        let r = kem::decapsulate(
            &DecapsulationKey { algorithm: alg, bytes: bytes.clone() },
            &Ciphertext { algorithm: alg, bytes: good_ct },
        );
        prop_assert_eq!(r.is_ok(), bytes.len() == 64);
        let r = kem::decapsulate(
            &DecapsulationKey { algorithm: alg, bytes: good_seed.to_vec() },
            &Ciphertext { algorithm: alg, bytes: bytes.clone() },
        );
        prop_assert_eq!(r.is_ok(), bytes.len() == ct_len);
        let r = kem::encapsulate(&EncapsulationKey { algorithm: alg, bytes: bytes.clone() });
        if bytes.len() != ek_len {
            prop_assert!(r.is_err());
        }
    }

    /// FIPS 203 section 7.2 modulus check: an encapsulation key whose coefficients are all
    /// below q = 3329 is accepted, and one coefficient of q or more makes it an error.
    #[test]
    fn kem_encapsulation_key_check(
        alg in kem_alg(),
        coeffs in prop::collection::vec(0u16..3329, 1024),
        rho in any::<[u8; 32]>(),
        bad_index in any::<prop::sample::Index>(),
        bad_value in 3329u16..4096,
    ) {
        let (k, ek_len, _) = kem_sizes(alg);
        let mut coeffs = coeffs[..256 * k].to_vec();
        let ek = encode_ek(&coeffs, &rho);
        prop_assert_eq!(ek.len(), ek_len);
        let good = kem::encapsulate(&EncapsulationKey { algorithm: alg, bytes: ek });
        prop_assert!(good.is_ok());
        let i = bad_index.index(coeffs.len());
        coeffs[i] = bad_value;
        let ek = encode_ek(&coeffs, &rho);
        let bad = kem::encapsulate(&EncapsulationKey { algorithm: alg, bytes: ek });
        prop_assert!(bad.is_err());
    }

    /// Wrong key: a ciphertext for one seed, decapsulated with any other seed, gives that
    /// seed's implicit-rejection key J(z' || c), never the encapsulated secret.
    #[test]
    fn kem_wrong_decapsulation_key_gives_implicit_rejection_key(
        alg in kem_alg(),
        a in any::<[u8; 64]>(),
        b in any::<[u8; 64]>(),
    ) {
        prop_assume!(a != b);
        let (ek, _) = kem_pair(alg, a);
        let (_, wrong) = kem_pair(alg, b);
        let (ct, ss) = kem::encapsulate(&ek).unwrap();
        let got = kem::decapsulate(&wrong, &ct).unwrap();
        // z (the last 32 bytes) is used only for rejection: two seeds that share d (the first
        // 32 bytes) are the same key pair. Random seeds share d with probability 2^-256.
        if a[..32] == b[..32] {
            prop_assert_eq!(&got.bytes, &ss.bytes);
        } else {
            prop_assert_ne!(&got.bytes, &ss.bytes);
            prop_assert_eq!(&got.bytes, &implicit_rejection_key(&b[32..], &ct.bytes));
        }
    }

    /// Encodings round-trip through the backend: the 64-byte seed and the encapsulation key.
    #[test]
    fn kem_encodings_round_trip(alg in kem_alg(), seed in any::<[u8; 64]>()) {
        use ml_kem::{KeyExport, KeyInit, TryKeyInit};
        let ek = ek_from_seed(alg, &seed);
        let s = ml_kem::Seed::from(seed);
        let (seed_back, ek_back) = match alg {
            KemAlgorithm::MlKem512 => (
                ml_kem::DecapsulationKey::<ml_kem::MlKem512>::new(&s).to_seed().unwrap().to_vec(),
                ml_kem::EncapsulationKey::<ml_kem::MlKem512>::new_from_slice(&ek).unwrap().to_bytes().to_vec(),
            ),
            KemAlgorithm::MlKem768 => (
                ml_kem::DecapsulationKey::<ml_kem::MlKem768>::new(&s).to_seed().unwrap().to_vec(),
                ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(&ek).unwrap().to_bytes().to_vec(),
            ),
            KemAlgorithm::MlKem1024 => (
                ml_kem::DecapsulationKey::<ml_kem::MlKem1024>::new(&s).to_seed().unwrap().to_vec(),
                ml_kem::EncapsulationKey::<ml_kem::MlKem1024>::new_from_slice(&ek).unwrap().to_bytes().to_vec(),
            ),
        };
        prop_assert_eq!(seed_back, seed.to_vec());
        prop_assert_eq!(ek_back, ek);
    }
}

// ── Signatures ──────────────────────────────────────────────────────────────

#[cfg(feature = "sign")]
mod signatures {
    use super::*;
    use paraxiom_pqc::sign::{self, SignAlgorithm, Signature, SigningKey, VerificationKey};
    use std::sync::OnceLock;

    const ML_DSA: [SignAlgorithm; 3] = [
        SignAlgorithm::MlDsa44,
        SignAlgorithm::MlDsa65,
        SignAlgorithm::MlDsa87,
    ];

    /// Every scheme whose signing is built on this host.
    fn signing_algs() -> Vec<SignAlgorithm> {
        let mut v = vec![
            SignAlgorithm::MlDsa44,
            SignAlgorithm::MlDsa65,
            SignAlgorithm::MlDsa87,
            SignAlgorithm::SlhDsaShake128f,
            SignAlgorithm::SlhDsaShake256s,
        ];
        if sign::FALCON_SIGNING_AVAILABLE {
            v.extend([SignAlgorithm::Falcon512, SignAlgorithm::Falcon1024]);
        }
        v
    }

    fn ml_dsa_alg() -> impl Strategy<Value = SignAlgorithm> {
        prop::sample::select(ML_DSA.to_vec())
    }

    fn any_alg() -> impl Strategy<Value = SignAlgorithm> {
        prop::sample::select(signing_algs())
    }

    /// The verification key `sign::keypair` stores for an ML-DSA seed.
    fn ml_dsa_vk(alg: SignAlgorithm, seed: &[u8; 32]) -> Vec<u8> {
        fn vk<P: ml_dsa::MlDsaParams>(seed: &[u8; 32]) -> Vec<u8> {
            ml_dsa::SigningKey::<P>::from_seed(&ml_dsa::B32::from(*seed))
                .verifying_key()
                .encode()
                .to_vec()
        }
        match alg {
            SignAlgorithm::MlDsa44 => vk::<ml_dsa::MlDsa44>(seed),
            SignAlgorithm::MlDsa65 => vk::<ml_dsa::MlDsa65>(seed),
            SignAlgorithm::MlDsa87 => vk::<ml_dsa::MlDsa87>(seed),
            _ => unreachable!(),
        }
    }

    /// Deterministic ML-DSA.Sign through upstream's variable-length loop.
    fn ml_dsa_reference(
        alg: SignAlgorithm,
        seed: &[u8; 32],
        msg: &[u8],
        ctx: &[u8],
    ) -> Option<Vec<u8>> {
        fn r<P: ml_dsa::MlDsaParams>(seed: &[u8; 32], msg: &[u8], ctx: &[u8]) -> Option<Vec<u8>> {
            let sk = ml_dsa::SigningKey::<P>::from_seed(&ml_dsa::B32::from(*seed));
            sk.sign_deterministic(msg, ctx)
                .ok()
                .map(|s| s.encode().to_vec())
        }
        match alg {
            SignAlgorithm::MlDsa44 => r::<ml_dsa::MlDsa44>(seed, msg, ctx),
            SignAlgorithm::MlDsa65 => r::<ml_dsa::MlDsa65>(seed, msg, ctx),
            SignAlgorithm::MlDsa87 => r::<ml_dsa::MlDsa87>(seed, msg, ctx),
            _ => unreachable!(),
        }
    }

    /// The fixed-round kernel, called directly.
    fn ml_dsa_kernel(
        alg: SignAlgorithm,
        seed: &[u8; 32],
        msg: &[u8],
        ctx: &[u8],
    ) -> Option<Vec<u8>> {
        fn k<P: ml_dsa::MlDsaParams>(seed: &[u8; 32], msg: &[u8], ctx: &[u8]) -> Option<Vec<u8>> {
            let sk = ml_dsa::SigningKey::<P>::from_seed(&ml_dsa::B32::from(*seed));
            sk.sign_deterministic_constant_time(msg, ctx)
                .ok()
                .map(|s| s.encode().to_vec())
        }
        match alg {
            SignAlgorithm::MlDsa44 => k::<ml_dsa::MlDsa44>(seed, msg, ctx),
            SignAlgorithm::MlDsa65 => k::<ml_dsa::MlDsa65>(seed, msg, ctx),
            SignAlgorithm::MlDsa87 => k::<ml_dsa::MlDsa87>(seed, msg, ctx),
            _ => unreachable!(),
        }
    }

    /// One key pair, message and signature per scheme, made once: (vk, msg, sig).
    struct Fixture {
        alg: SignAlgorithm,
        sk: SigningKey,
        vk: VerificationKey,
        msg: Vec<u8>,
        sig: Signature,
    }

    /// Made at run time with `sign::keypair` and `sign::sign`, except SLH-DSA-SHAKE-256s:
    /// signing takes about a minute in a debug build, so its fixture is the NIST ACVP sigGen
    /// vector with an empty context (tests/acvp), which `sign::sign` reproduces byte for byte
    /// (tests/acvp.rs).
    fn fixtures() -> &'static Vec<Fixture> {
        static F: OnceLock<Vec<Fixture>> = OnceLock::new();
        F.get_or_init(|| {
            signing_algs()
                .into_iter()
                .map(|alg| {
                    if alg == SignAlgorithm::SlhDsaShake256s {
                        return nist_slh_dsa_256s_fixture();
                    }
                    let kp = sign::keypair(alg).unwrap();
                    let msg = format!("paraxiom-pqc property fixture {alg:?}").into_bytes();
                    let sig = sign::sign(&kp.sk, &msg).unwrap();
                    Fixture {
                        alg,
                        sk: kp.sk,
                        vk: kp.vk,
                        msg,
                        sig,
                    }
                })
                .collect()
        })
    }

    fn nist_slh_dsa_256s_fixture() -> Fixture {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/acvp/SLH-DSA-sigGen-FIPS205.json"
        );
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let unhex = |v: &serde_json::Value| -> Vec<u8> {
            let s = v.as_str().unwrap();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let alg = SignAlgorithm::SlhDsaShake256s;
        for g in file["testGroups"].as_array().unwrap() {
            if g["parameterSet"] != "SLH-DSA-SHAKE-256s" {
                continue;
            }
            for t in g["tests"].as_array().unwrap() {
                if t["context"] == "" {
                    return Fixture {
                        alg,
                        sk: SigningKey {
                            algorithm: alg,
                            bytes: unhex(&t["sk"]),
                        },
                        vk: VerificationKey {
                            algorithm: alg,
                            bytes: unhex(&t["pk"]),
                        },
                        msg: unhex(&t["message"]),
                        sig: Signature {
                            algorithm: alg,
                            bytes: unhex(&t["signature"]),
                        },
                    };
                }
            }
        }
        panic!("no SLH-DSA-SHAKE-256s vector with an empty context");
    }

    fn fixture(alg: SignAlgorithm) -> &'static Fixture {
        fixtures().iter().find(|f| f.alg == alg).unwrap()
    }

    fn accepted(vk: &VerificationKey, msg: &[u8], sig: &Signature) -> bool {
        matches!(sign::verify(vk, msg, sig), Ok(true))
    }

    fn flip_bit(bytes: &[u8], bit: prop::sample::Index) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let b = bit.index(out.len() * 8);
        out[b / 8] ^= 1 << (b % 8);
        out
    }

    #[test]
    fn fixtures_verify() {
        for f in fixtures() {
            assert!(accepted(&f.vk, &f.msg, &f.sig), "{:?}", f.alg);
        }
    }

    proptest! {
        #![proptest_config(config(8))]

        /// ML-DSA from any 32-byte seed: `sign` and `sign_randomized` (hedged) and
        /// `sign_deterministic_dangerous` all verify, the deterministic one equals upstream's
        /// deterministic ML-DSA.Sign, and another message is refused.
        #[test]
        fn ml_dsa_round_trip_from_any_seed(
            alg in ml_dsa_alg(),
            seed in any::<[u8; 32]>(),
            msg in prop::collection::vec(any::<u8>(), 0..300),
        ) {
            let sk = SigningKey { algorithm: alg, bytes: seed.to_vec() };
            let vk = VerificationKey { algorithm: alg, bytes: ml_dsa_vk(alg, &seed) };
            let hedged = sign::sign(&sk, &msg).unwrap();
            let randomized = sign::sign_randomized(&sk, &msg).unwrap();
            let det = sign::sign_deterministic_dangerous(&sk, &msg).unwrap();
            for s in [&hedged, &randomized, &det] {
                prop_assert!(accepted(&vk, &msg, s));
                prop_assert_eq!(s.algorithm, alg);
            }
            prop_assert_eq!(Some(det.bytes.clone()), ml_dsa_reference(alg, &seed, &msg, b""));
            let mut other = msg.clone();
            other.push(0);
            prop_assert!(!accepted(&vk, &other, &det));
        }

        /// The fixed-round kernel returns exactly upstream's deterministic signature, for any
        /// seed, message and context (contexts over 255 bytes are refused by both).
        #[test]
        fn kernel_equals_deterministic_sign(
            alg in ml_dsa_alg(),
            seed in any::<[u8; 32]>(),
            msg in prop::collection::vec(any::<u8>(), 0..1100),
            ctx in prop::collection::vec(any::<u8>(), 0..=257),
        ) {
            let kernel = ml_dsa_kernel(alg, &seed, &msg, &ctx);
            let reference = ml_dsa_reference(alg, &seed, &msg, &ctx);
            prop_assert_eq!(kernel.is_some(), ctx.len() <= 255);
            prop_assert_eq!(kernel, reference);
        }

        /// Every scheme signs and verifies a fresh message with all three signing functions;
        /// signing keys and verification keys copied into new values (as after storage) work
        /// the same.
        #[test]
        fn sign_verify_round_trip(alg in any_alg(), msg in prop::collection::vec(any::<u8>(), 0..300)) {
            if alg == SignAlgorithm::SlhDsaShake256s && cfg!(debug_assertions) {
                return Ok(()); // a minute per signature in debug builds; release runs it
            }
            let f = fixture(alg);
            let sk = SigningKey { algorithm: alg, bytes: f.sk.bytes.clone() };
            let vk = VerificationKey { algorithm: alg, bytes: f.vk.bytes.clone() };
            for s in [
                sign::sign(&sk, &msg).unwrap(),
                sign::sign_randomized(&sk, &msg).unwrap(),
                sign::sign_deterministic_dangerous(&sk, &msg).unwrap(),
            ] {
                prop_assert_eq!(s.algorithm, alg);
                prop_assert!(accepted(&vk, &msg, &s), "{:?}", alg);
            }
        }
    }

    proptest! {
        #![proptest_config(config(32))]

        /// One flipped bit anywhere in the signature, and it is refused (`Ok(false)` or an
        /// error), never accepted and never a panic.
        #[test]
        fn flipped_signature_bit_is_refused(alg in any_alg(), bit in any::<prop::sample::Index>()) {
            let f = fixture(alg);
            let sig = Signature { algorithm: alg, bytes: flip_bit(&f.sig.bytes, bit) };
            prop_assert!(!accepted(&f.vk, &f.msg, &sig), "{:?}", alg);
        }

        /// One flipped bit in the message, and the signature is refused.
        #[test]
        fn flipped_message_bit_is_refused(alg in any_alg(), bit in any::<prop::sample::Index>()) {
            let f = fixture(alg);
            prop_assert!(!accepted(&f.vk, &flip_bit(&f.msg, bit), &f.sig), "{:?}", alg);
        }

        /// One flipped bit in the verification key, and the signature is refused.
        #[test]
        fn flipped_verification_key_bit_is_refused(alg in any_alg(), bit in any::<prop::sample::Index>()) {
            let f = fixture(alg);
            let vk = VerificationKey { algorithm: alg, bytes: flip_bit(&f.vk.bytes, bit) };
            prop_assert!(!accepted(&vk, &f.msg, &f.sig), "{:?}", alg);
        }

        /// Arbitrary verification keys and signatures, of any length, give `Ok(false)` or an
        /// error. Lengths near the real ones are favoured so that parsing goes deep.
        #[test]
        fn verify_never_accepts_or_panics_on_garbage(
            alg in prop::sample::select(vec![
                SignAlgorithm::MlDsa44, SignAlgorithm::MlDsa65, SignAlgorithm::MlDsa87,
                SignAlgorithm::SlhDsaShake128f, SignAlgorithm::SlhDsaShake256s,
                SignAlgorithm::Falcon512, SignAlgorithm::Falcon1024,
            ]),
            exact_len in any::<bool>(),
            vk_noise in prop::collection::vec(any::<u8>(), 0..2700),
            sig_noise in prop::collection::vec(any::<u8>(), 0..5000),
            msg in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let (vk_len, sig_len) = sizes(alg);
            let fit = |noise: &[u8], len: usize| {
                if exact_len { noise.iter().copied().cycle().take(len).collect::<Vec<_>>() } else { noise.to_vec() }
            };
            let vk = VerificationKey { algorithm: alg, bytes: if vk_noise.is_empty() { vec![] } else { fit(&vk_noise, vk_len) } };
            let sig = Signature { algorithm: alg, bytes: if sig_noise.is_empty() { vec![] } else { fit(&sig_noise, sig_len) } };
            prop_assert!(!accepted(&vk, &msg, &sig));
        }

        /// A signing key of the wrong length is an error from all three signing functions.
        #[test]
        fn wrong_length_signing_key_is_an_error(
            alg in prop::sample::select(vec![
                SignAlgorithm::MlDsa44, SignAlgorithm::MlDsa65, SignAlgorithm::MlDsa87,
                SignAlgorithm::SlhDsaShake128f, SignAlgorithm::SlhDsaShake256s,
                SignAlgorithm::Falcon512, SignAlgorithm::Falcon1024,
            ]),
            bytes in prop::collection::vec(any::<u8>(), 0..3000),
        ) {
            let right = match alg {
                SignAlgorithm::MlDsa44 | SignAlgorithm::MlDsa65 | SignAlgorithm::MlDsa87 => 32,
                SignAlgorithm::SlhDsaShake128f => 64,
                SignAlgorithm::SlhDsaShake256s => 128,
                SignAlgorithm::Falcon512 => 1281,
                SignAlgorithm::Falcon1024 => 2305,
            };
            prop_assume!(bytes.len() != right);
            let sk = SigningKey { algorithm: alg, bytes };
            prop_assert!(sign::sign(&sk, b"m").is_err());
            prop_assert!(sign::sign_randomized(&sk, b"m").is_err());
            prop_assert!(sign::sign_deterministic_dangerous(&sk, b"m").is_err());
        }
    }

    /// (verification key length, signature length) per scheme.
    fn sizes(alg: SignAlgorithm) -> (usize, usize) {
        match alg {
            SignAlgorithm::MlDsa44 => (1312, 2420),
            SignAlgorithm::MlDsa65 => (1952, 3309),
            SignAlgorithm::MlDsa87 => (2592, 4627),
            SignAlgorithm::SlhDsaShake128f => (32, 17088),
            SignAlgorithm::SlhDsaShake256s => (64, 29792),
            SignAlgorithm::Falcon512 => (897, 809),
            SignAlgorithm::Falcon1024 => (1793, 1577),
        }
    }

    /// The key, signature and verification-key lengths of every scheme are the published ones,
    /// and each encoding round-trips through the backend that parses it: decode then encode
    /// gives the same bytes.
    #[test]
    fn encodings_have_published_sizes_and_round_trip() {
        for f in fixtures() {
            let (vk_len, sig_len) = sizes(f.alg);
            assert_eq!(
                (f.vk.bytes.len(), f.sig.bytes.len()),
                (vk_len, sig_len),
                "{:?}",
                f.alg
            );
            match f.alg {
                SignAlgorithm::MlDsa44 => ml_dsa_codec::<ml_dsa::MlDsa44>(f),
                SignAlgorithm::MlDsa65 => ml_dsa_codec::<ml_dsa::MlDsa65>(f),
                SignAlgorithm::MlDsa87 => ml_dsa_codec::<ml_dsa::MlDsa87>(f),
                SignAlgorithm::SlhDsaShake128f => slh_dsa_codec::<slh_dsa::Shake128f>(f),
                SignAlgorithm::SlhDsaShake256s => slh_dsa_codec::<slh_dsa::Shake256s>(f),
                SignAlgorithm::Falcon512 | SignAlgorithm::Falcon1024 => {
                    let kp = falcon::safe_api::FnDsaKeyPair::from_private_key(&f.sk.bytes).unwrap();
                    assert_eq!(kp.private_key(), f.sk.bytes.as_slice());
                    assert_eq!(
                        kp.public_key(),
                        f.vk.bytes.as_slice(),
                        "vk is derived from sk"
                    );
                    let sig =
                        falcon::safe_api::FnDsaSignature::from_bytes(f.sig.bytes.clone()).unwrap();
                    assert_eq!(sig.to_bytes(), f.sig.bytes.as_slice());
                }
            }
        }
    }

    fn ml_dsa_codec<P: ml_dsa::MlDsaParams>(f: &Fixture) {
        assert_eq!(f.sk.bytes.len(), 32);
        let seed: [u8; 32] = f.sk.bytes.as_slice().try_into().unwrap();
        assert_eq!(
            ml_dsa_vk(f.alg, &seed),
            f.vk.bytes,
            "vk is derived from the seed"
        );
        let enc_vk = ml_dsa::EncodedVerifyingKey::<P>::try_from(f.vk.bytes.as_slice()).unwrap();
        assert_eq!(ml_dsa::VerifyingKey::<P>::decode(&enc_vk).encode(), enc_vk);
        let enc_sig = ml_dsa::EncodedSignature::<P>::try_from(f.sig.bytes.as_slice()).unwrap();
        assert_eq!(
            ml_dsa::Signature::<P>::decode(&enc_sig).unwrap().encode(),
            enc_sig
        );
    }

    fn slh_dsa_codec<P: slh_dsa::ParameterSet>(f: &Fixture) {
        let sk = slh_dsa::SigningKey::<P>::try_from(f.sk.bytes.as_slice()).unwrap();
        assert_eq!(sk.to_vec(), f.sk.bytes);
        let vk: &slh_dsa::VerifyingKey<P> = sk.as_ref();
        assert_eq!(vk.to_vec(), f.vk.bytes, "vk is the second half of sk");
        let vk = slh_dsa::VerifyingKey::<P>::try_from(f.vk.bytes.as_slice()).unwrap();
        assert_eq!(vk.to_vec(), f.vk.bytes);
        let sig = slh_dsa::Signature::<P>::try_from(f.sig.bytes.as_slice()).unwrap();
        assert_eq!(sig.to_vec(), f.sig.bytes);
    }

    /// `sign` is hedged for ML-DSA and Falcon (two signatures of one message differ) and
    /// deterministic for SLH-DSA; `sign_deterministic_dangerous` is deterministic everywhere
    /// except Falcon, which is randomized by construction.
    #[test]
    fn determinism_matches_the_documentation() {
        for f in fixtures() {
            if f.alg == SignAlgorithm::SlhDsaShake256s && cfg!(debug_assertions) {
                continue;
            }
            let a = sign::sign(&f.sk, &f.msg).unwrap().bytes;
            let b = sign::sign(&f.sk, &f.msg).unwrap().bytes;
            let slh = matches!(
                f.alg,
                SignAlgorithm::SlhDsaShake128f | SignAlgorithm::SlhDsaShake256s
            );
            let falcon = matches!(f.alg, SignAlgorithm::Falcon512 | SignAlgorithm::Falcon1024);
            assert_eq!(a == b, slh, "sign {:?}", f.alg);
            let c = sign::sign_deterministic_dangerous(&f.sk, &f.msg)
                .unwrap()
                .bytes;
            let d = sign::sign_deterministic_dangerous(&f.sk, &f.msg)
                .unwrap()
                .bytes;
            assert_eq!(c == d, !falcon, "sign_deterministic_dangerous {:?}", f.alg);
        }
    }

    /// A signature made for one scheme, presented with the same bytes as another scheme's,
    /// is never accepted, and does not panic. This includes Falcon-512 presented as Falcon-1024
    /// and back, which `sign::verify` accepted before 0.2.0 (tests/falcon_verify.rs).
    #[test]
    fn signatures_do_not_cross_schemes() {
        for f in fixtures() {
            for other in signing_algs() {
                if other == f.alg {
                    continue;
                }
                let vk = VerificationKey {
                    algorithm: other,
                    bytes: f.vk.bytes.clone(),
                };
                let sig = Signature {
                    algorithm: other,
                    bytes: f.sig.bytes.clone(),
                };
                assert!(!accepted(&vk, &f.msg, &sig), "{:?} as {:?}", f.alg, other);
            }
        }
    }

    /// A second key pair per scheme, independent of the fixtures.
    fn other_keys() -> &'static Vec<(SignAlgorithm, VerificationKey)> {
        static K: OnceLock<Vec<(SignAlgorithm, VerificationKey)>> = OnceLock::new();
        K.get_or_init(|| {
            signing_algs()
                .into_iter()
                .map(|alg| (alg, sign::keypair(alg).unwrap().vk))
                .collect()
        })
    }

    /// Wrong key: each scheme's fixture signature is refused under another valid verification
    /// key of the same scheme.
    #[test]
    fn signature_is_refused_under_another_valid_key() {
        for f in fixtures() {
            let (_, other) = other_keys().iter().find(|(a, _)| *a == f.alg).unwrap();
            assert_ne!(other.bytes, f.vk.bytes, "{:?}", f.alg);
            assert!(!accepted(other, &f.msg, &f.sig), "{:?}", f.alg);
        }
    }

    proptest! {
        #![proptest_config(config(16))]

        /// Wrong key, ML-DSA from any two different seeds: a signature by one is refused under
        /// the other's verification key, from all three signing functions.
        #[test]
        fn ml_dsa_signature_is_refused_under_another_seeds_key(
            alg in ml_dsa_alg(),
            a in any::<[u8; 32]>(),
            b in any::<[u8; 32]>(),
            msg in prop::collection::vec(any::<u8>(), 0..200),
        ) {
            prop_assume!(a != b);
            let sk = SigningKey { algorithm: alg, bytes: a.to_vec() };
            let wrong = VerificationKey { algorithm: alg, bytes: ml_dsa_vk(alg, &b) };
            for s in [
                sign::sign(&sk, &msg).unwrap(),
                sign::sign_randomized(&sk, &msg).unwrap(),
                sign::sign_deterministic_dangerous(&sk, &msg).unwrap(),
            ] {
                prop_assert!(!accepted(&wrong, &msg, &s));
            }
        }

        /// Signing keys of the right length with arbitrary contents: no panic from any of the
        /// three signing functions, and whatever they return is refused under another key.
        /// ML-DSA and SLH-DSA-SHAKE-128f accept every byte string of the right length as a key;
        /// a Falcon key must also carry the header of its degree, which is set here so that
        /// parsing goes past it.
        #[test]
        fn arbitrary_signing_key_of_the_right_length_does_not_panic(
            alg in prop::sample::select(
                signing_algs().into_iter().filter(|a| *a != SignAlgorithm::SlhDsaShake256s).collect::<Vec<_>>()
            ),
            noise in prop::collection::vec(any::<u8>(), 2305),
        ) {
            let mut bytes = match alg {
                SignAlgorithm::MlDsa44 | SignAlgorithm::MlDsa65 | SignAlgorithm::MlDsa87 => noise[..32].to_vec(),
                SignAlgorithm::SlhDsaShake128f => noise[..64].to_vec(),
                SignAlgorithm::Falcon512 => noise[..1281].to_vec(),
                _ => noise.clone(),
            };
            match alg {
                SignAlgorithm::Falcon512 => bytes[0] = 0x59,
                SignAlgorithm::Falcon1024 => bytes[0] = 0x5A,
                _ => {}
            }
            let sk = SigningKey { algorithm: alg, bytes };
            let (_, wrong) = other_keys().iter().find(|(a, _)| *a == alg).unwrap();
            for r in [
                sign::sign(&sk, b"m"),
                sign::sign_randomized(&sk, b"m"),
                sign::sign_deterministic_dangerous(&sk, b"m"),
            ] {
                if let Ok(s) = r {
                    prop_assert!(!accepted(wrong, b"m", &s));
                }
            }
        }
    }
}
