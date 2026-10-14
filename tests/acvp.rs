//! NIST ACVP known-answer tests for ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
//!
//! The vectors in `tests/acvp/*.json` are subsets of the NIST ACVP-Server files; see
//! `tests/acvp/README.md` for the source commit and the selection rules.
//!
//! Where the public API can take a vector, the test goes through it (`kem::encapsulate` on the
//! encapsulation-key checks, `sign::sign` and `sign::verify` on SLH-DSA, the ML-KEM and ML-DSA
//! seeds as `DecapsulationKey` and `SigningKey`). Where it cannot (expanded keys, injected
//! randomness), the test calls the backend function that the wrapper calls, with the same
//! arguments the wrapper passes.
//!
//! The SLH-DSA-SHAKE-256s signing vectors take minutes in a debug build and are `#[ignore]`d;
//! run them with `cargo test --release --test acvp -- --ignored`.

use paraxiom_pqc::kem::{self, Ciphertext, DecapsulationKey, EncapsulationKey, KemAlgorithm};
use serde_json::Value;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::path::Path;

fn load(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/acvp")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Calls `f(group, test)` for every test case and returns how many there were.
fn each_test(file: &Value, mut f: impl FnMut(&Value, &Value)) -> usize {
    let mut n = 0;
    for g in file["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            f(g, t);
            n += 1;
        }
    }
    n
}

/// ML-KEM.Decaps implicit rejection key, FIPS 203 Algorithm 18 line 7: K' = J(z || c), with
/// J(s) = SHAKE256(s, 8 * 32). Computed here independently of ml-kem.
fn implicit_rejection_key(z: &[u8], c: &[u8]) -> Vec<u8> {
    let mut h = sha3::Shake256::default();
    h.update(z);
    h.update(c);
    let mut out = vec![0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

fn kem_alg(set: &str) -> KemAlgorithm {
    match set {
        "ML-KEM-512" => KemAlgorithm::MlKem512,
        "ML-KEM-768" => KemAlgorithm::MlKem768,
        "ML-KEM-1024" => KemAlgorithm::MlKem1024,
        other => panic!("unexpected parameter set {other}"),
    }
}

/// Runs `$body` with `$P` bound to the ml-kem parameter type of `$alg`.
macro_rules! with_ml_kem {
    ($alg:expr, $P:ident => $body:block) => {
        match $alg {
            KemAlgorithm::MlKem512 => {
                type $P = ml_kem::MlKem512;
                $body
            }
            KemAlgorithm::MlKem768 => {
                type $P = ml_kem::MlKem768;
                $body
            }
            KemAlgorithm::MlKem1024 => {
                type $P = ml_kem::MlKem1024;
                $body
            }
        }
    };
}

// ── ML-KEM (FIPS 203) ──────────────────────────────────────────────────────

/// keyGen: the 64-byte seed d || z that `kem::DecapsulationKey` stores rebuilds NIST's ek and
/// expanded dk, and the wrapper uses it the way NIST does: a key pair made of the NIST seed and
/// the NIST ek round-trips through `kem::encapsulate` / `kem::decapsulate`, and a modified
/// ciphertext decapsulates to J(z || c) with NIST's z.
#[test]
fn ml_kem_keygen_matches_acvp() {
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;
    use ml_kem::{KeyExport, KeyInit};

    let file = load("ML-KEM-keyGen-FIPS203");
    let n = each_test(&file, |g, t| {
        let alg = kem_alg(g["parameterSet"].as_str().unwrap());
        let (d, z, ek, dk) = (
            unhex(&t["d"]),
            unhex(&t["z"]),
            unhex(&t["ek"]),
            unhex(&t["dk"]),
        );
        let seed: Vec<u8> = d.iter().chain(z.iter()).copied().collect();
        let tc = &t["tcId"];

        // Backend, called exactly as kem::decapsulate builds its key (KeyInit::new on the seed),
        // and read back as kem::keypair reads it (encapsulation_key().to_bytes(), to_seed()).
        with_ml_kem!(alg, P => {
            let seed_arr = ml_kem::Seed::try_from(seed.as_slice()).unwrap();
            let dk_t = ml_kem::DecapsulationKey::<P>::new(&seed_arr);
            assert_eq!(dk_t.encapsulation_key().to_bytes().as_slice(), ek.as_slice(), "tc {tc}: ek");
            #[allow(deprecated)]
            let expanded = dk_t.to_expanded_bytes();
            assert_eq!(expanded.as_slice(), dk.as_slice(), "tc {tc}: dk");
            assert_eq!(dk_t.to_seed().unwrap().as_slice(), seed.as_slice(), "tc {tc}: seed order");
        });

        // Public API with the NIST key pair.
        let ek_w = EncapsulationKey {
            algorithm: alg,
            bytes: ek.clone(),
        };
        let dk_w = DecapsulationKey {
            algorithm: alg,
            bytes: seed.clone(),
        };
        let (ct, ss) = kem::encapsulate(&ek_w).unwrap();
        let ss2 = kem::decapsulate(&dk_w, &ct).unwrap();
        assert_eq!(ss.bytes, ss2.bytes, "tc {tc}: round trip");

        let mut bad = ct.bytes.clone();
        bad[0] ^= 1;
        let rejected = kem::decapsulate(
            &dk_w,
            &Ciphertext {
                algorithm: alg,
                bytes: bad.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            rejected.bytes,
            implicit_rejection_key(&z, &bad),
            "tc {tc}: implicit rejection"
        );
        assert_ne!(rejected.bytes, ss.bytes, "tc {tc}");
    });
    assert_eq!(n, 30);
}

/// encapsulation: ek and m give NIST's c and K. The wrapper's `encapsulate` parses ek with
/// `TryKeyInit::new_from_slice` and then calls `encapsulate`, which draws m and runs
/// `encapsulate_deterministic`; this runs that last step with NIST's m.
#[test]
fn ml_kem_encapsulation_matches_acvp() {
    use ml_kem::TryKeyInit;

    let file = load("ML-KEM-encapDecap-FIPS203");
    let mut n = 0;
    each_test(&file, |g, t| {
        if g["function"] != "encapsulation" {
            return;
        }
        n += 1;
        let alg = kem_alg(g["parameterSet"].as_str().unwrap());
        let (ek, m, c, k) = (
            unhex(&t["ek"]),
            unhex(&t["m"]),
            unhex(&t["c"]),
            unhex(&t["k"]),
        );
        let tc = &t["tcId"];
        with_ml_kem!(alg, P => {
            let ek_t = ml_kem::EncapsulationKey::<P>::new_from_slice(&ek).unwrap();
            let m = ml_kem::B32::try_from(m.as_slice()).unwrap();
            let (c_t, k_t) = ek_t.encapsulate_deterministic(&m);
            assert_eq!(c_t.as_slice(), c.as_slice(), "tc {tc}: c");
            assert_eq!(k_t.as_slice(), k.as_slice(), "tc {tc}: K");
        });
        // The wrapper accepts the key and produces a ciphertext of NIST's length.
        let (ct, ss) = kem::encapsulate(&EncapsulationKey {
            algorithm: alg,
            bytes: ek,
        })
        .unwrap();
        assert_eq!((ct.bytes.len(), ss.bytes.len()), (c.len(), 32), "tc {tc}");
    });
    assert_eq!(n, 30);
}

/// decapsulation (valid and modified ciphertexts): the backend decapsulates NIST's expanded dk
/// to NIST's K. The wrapper only takes seeds, so it cannot be given these keys; for modified
/// ciphertexts the expected K is also checked against J(z || c) computed here, which validates
/// the oracle that the keyGen test and the property tests use on the wrapper.
#[test]
fn ml_kem_decapsulation_matches_acvp() {
    use ml_kem::Decapsulate;
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;

    let file = load("ML-KEM-encapDecap-FIPS203");
    let (mut valid, mut modified) = (0, 0);
    each_test(&file, |g, t| {
        if g["function"] != "decapsulation" {
            return;
        }
        let alg = kem_alg(g["parameterSet"].as_str().unwrap());
        let (dk, c, k) = (unhex(&t["dk"]), unhex(&t["c"]), unhex(&t["k"]));
        let tc = &t["tcId"];
        with_ml_kem!(alg, P => {
            #[allow(deprecated)]
            let enc = ml_kem::ExpandedDecapsulationKey::<P>::try_from(dk.as_slice()).unwrap();
            #[allow(deprecated)]
            let dk_t = ml_kem::DecapsulationKey::<P>::from_expanded_bytes(&enc).unwrap();
            let c_t = ml_kem::Ciphertext::<P>::try_from(c.as_slice()).unwrap();
            assert_eq!(dk_t.decapsulate(&c_t).as_slice(), k.as_slice(), "tc {tc}");
        });
        match t["reason"].as_str().unwrap() {
            "valid decapsulation" => valid += 1,
            "modified ciphertext" => {
                modified += 1;
                let z = &dk[dk.len() - 32..];
                assert_eq!(implicit_rejection_key(z, &c), k, "tc {tc}: J(z || c)");
            }
            other => panic!("tc {tc}: unexpected reason {other}"),
        }
    });
    assert_eq!((valid, modified), (15, 15));
}

/// encapsulationKeyCheck (FIPS 203 section 7.2, modulus check), through the public API:
/// `kem::encapsulate` accepts exactly the keys NIST marks as valid.
#[test]
fn ml_kem_encapsulation_key_check_matches_acvp() {
    let file = load("ML-KEM-encapDecap-FIPS203");
    let (mut pass, mut fail) = (0, 0);
    each_test(&file, |g, t| {
        if g["function"] != "encapsulationKeyCheck" {
            return;
        }
        let alg = kem_alg(g["parameterSet"].as_str().unwrap());
        let ek = EncapsulationKey {
            algorithm: alg,
            bytes: unhex(&t["ek"]),
        };
        let expected = t["testPassed"].as_bool().unwrap();
        assert_eq!(
            kem::encapsulate(&ek).is_ok(),
            expected,
            "tc {}: {}",
            t["tcId"],
            t["reason"]
        );
        if expected {
            pass += 1;
        } else {
            fail += 1;
        }
    });
    assert_eq!((pass, fail), (15, 15));
}

// ── ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) ───────────────────────────────

#[cfg(feature = "sign")]
mod signatures {
    use super::*;
    use paraxiom_pqc::sign::{self, SignAlgorithm, Signature, SigningKey, VerificationKey};

    /// A "random" source that hands out the ACVP `rnd` bytes, so hedged signing is reproducible.
    struct FixedRng(Vec<u8>);

    impl rand_core::TryRng for FixedRng {
        type Error = rand_core::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unreachable!("ML-DSA draws rnd with fill_bytes")
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unreachable!("ML-DSA draws rnd with fill_bytes")
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            assert!(
                dst.len() <= self.0.len(),
                "more randomness drawn than rnd holds"
            );
            dst.copy_from_slice(&self.0[..dst.len()]);
            self.0.drain(..dst.len());
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for FixedRng {}

    fn ml_dsa_alg(set: &str) -> SignAlgorithm {
        match set {
            "ML-DSA-44" => SignAlgorithm::MlDsa44,
            "ML-DSA-65" => SignAlgorithm::MlDsa65,
            "ML-DSA-87" => SignAlgorithm::MlDsa87,
            other => panic!("unexpected parameter set {other}"),
        }
    }

    /// Calls the generic function `$f::<P>($args)` with `P` the ml-dsa parameter type of `$alg`.
    /// Each instance gets its own stack frame: in a debug build, three parameter sets' worth of
    /// keys in one frame overflow the 2 MiB test thread.
    macro_rules! ml_dsa_call {
        ($alg:expr, $f:ident($($args:expr),*)) => {
            match $alg {
                SignAlgorithm::MlDsa44 => $f::<ml_dsa::MlDsa44>($($args),*),
                SignAlgorithm::MlDsa65 => $f::<ml_dsa::MlDsa65>($($args),*),
                SignAlgorithm::MlDsa87 => $f::<ml_dsa::MlDsa87>($($args),*),
                other => panic!("not ML-DSA: {other:?}"),
            }
        };
    }

    #[allow(deprecated)]
    fn expanded_key<P: ml_dsa::MlDsaParams>(sk: &[u8]) -> ml_dsa::SigningKey<P> {
        let enc = ml_dsa::ExpandedSigningKey::<P>::try_from(sk).expect("expanded sk length");
        ml_dsa::SigningKey::<P>::from_expanded(&enc)
    }

    fn decode_vk<P: ml_dsa::MlDsaParams>(pk: &[u8]) -> ml_dsa::VerifyingKey<P> {
        let enc = ml_dsa::EncodedVerifyingKey::<P>::try_from(pk).expect("pk length");
        ml_dsa::VerifyingKey::<P>::decode(&enc)
    }

    #[allow(deprecated)]
    fn keygen_backend<P: ml_dsa::MlDsaParams>(t: &Value) {
        use ml_dsa::KeyGen;
        let (seed, pk, sk) = (unhex(&t["seed"]), unhex(&t["pk"]), unhex(&t["sk"]));
        let tc = &t["tcId"];
        let xi = ml_dsa::B32::try_from(seed.as_slice()).unwrap();

        let from_seed = ml_dsa::SigningKey::<P>::from_seed(&xi);
        assert_eq!(
            from_seed.verifying_key().encode().as_slice(),
            pk.as_slice(),
            "tc {tc}: pk"
        );
        assert_eq!(
            from_seed.to_expanded().as_slice(),
            sk.as_slice(),
            "tc {tc}: sk"
        );
        drop(from_seed);

        let kp = <P as KeyGen>::from_seed(&xi);
        assert_eq!(
            kp.verifying_key().encode().as_slice(),
            pk.as_slice(),
            "tc {tc}: kp pk"
        );
        assert_eq!(
            kp.signing_key().to_expanded().as_slice(),
            sk.as_slice(),
            "tc {tc}: kp sk"
        );
        assert_eq!(kp.to_seed().as_slice(), seed.as_slice(), "tc {tc}: kp seed");
    }

    fn deterministic_reference<P: ml_dsa::MlDsaParams>(sk: &[u8], msg: &[u8]) -> Vec<u8> {
        expanded_key::<P>(sk)
            .sign_deterministic(msg, b"")
            .unwrap()
            .encode()
            .to_vec()
    }

    /// keyGen: `SigningKey::from_seed` (rewritten on this branch to go through
    /// `keygen_internal` instead of a `KeyPair`) and `KeyGen::from_seed` both rebuild NIST's
    /// expanded sk and pk from the 32-byte seed. `verifying_key().encode()` is what
    /// `sign::keypair` stores as the verification key. Then the NIST seed and pk, used as a
    /// `sign::SigningKey` / `sign::VerificationKey`, sign and verify through the public API,
    /// and the deterministic path signs exactly like the NIST expanded key does.
    #[test]
    fn ml_dsa_keygen_matches_acvp() {
        let file = load("ML-DSA-keyGen-FIPS204");
        let mut first_of_set = std::collections::HashSet::new();
        let n = each_test(&file, |g, t| {
            let alg = ml_dsa_alg(g["parameterSet"].as_str().unwrap());
            ml_dsa_call!(alg, keygen_backend(t));

            // One key per parameter set through the public API (the kernel is slow in debug
            // builds).
            if first_of_set.insert(format!("{alg:?}")) {
                let tc = &t["tcId"];
                let (seed, pk, sk) = (unhex(&t["seed"]), unhex(&t["pk"]), unhex(&t["sk"]));
                let sk_w = SigningKey {
                    algorithm: alg,
                    bytes: seed,
                };
                let vk_w = VerificationKey {
                    algorithm: alg,
                    bytes: pk,
                };
                let msg = b"paraxiom-pqc ACVP keyGen cross-check";
                let hedged = sign::sign(&sk_w, msg).unwrap();
                assert!(
                    sign::verify(&vk_w, msg, &hedged).unwrap(),
                    "tc {tc}: hedged"
                );
                let det = sign::sign_deterministic_dangerous(&sk_w, msg).unwrap();
                assert!(
                    sign::verify(&vk_w, msg, &det).unwrap(),
                    "tc {tc}: deterministic"
                );
                let reference = ml_dsa_call!(alg, deterministic_reference(&sk, msg));
                assert_eq!(
                    det.bytes, reference,
                    "tc {tc}: same signature as the NIST key"
                );
            }
        });
        assert_eq!((n, first_of_set.len()), (30, 3));
    }

    fn deterministic_siggen_case<P: ml_dsa::MlDsaParams>(t: &Value) {
        let (pk, sk, msg, ctx, sig) = (
            unhex(&t["pk"]),
            unhex(&t["sk"]),
            unhex(&t["message"]),
            unhex(&t["context"]),
            unhex(&t["signature"]),
        );
        let tc = &t["tcId"];
        let key = expanded_key::<P>(&sk);
        let kernel = key.sign_deterministic_constant_time(&msg, &ctx).unwrap();
        assert_eq!(
            kernel.encode().as_slice(),
            sig.as_slice(),
            "tc {tc}: kernel"
        );
        let upstream = key.sign_deterministic(&msg, &ctx).unwrap();
        assert_eq!(
            upstream.encode().as_slice(),
            sig.as_slice(),
            "tc {tc}: upstream"
        );
        assert!(
            decode_vk::<P>(&pk).verify_with_context(&msg, &ctx, &kernel),
            "tc {tc}: verify"
        );
    }

    /// sigGen, deterministic, external interface, pure: the fixed-round kernel behind
    /// `sign_deterministic_dangerous` (`sign_deterministic_constant_time`) and upstream's
    /// variable-length `sign_deterministic` both return NIST's signature. The vectors include
    /// empty and 255-byte contexts and 1-byte messages. Empty-context signatures also verify
    /// through `sign::verify`.
    #[test]
    fn ml_dsa_deterministic_siggen_matches_acvp() {
        let file = load("ML-DSA-sigGen-FIPS204");
        let (mut n, mut through_wrapper) = (0, 0);
        each_test(&file, |g, t| {
            if g["deterministic"] != true {
                return;
            }
            n += 1;
            let alg = ml_dsa_alg(g["parameterSet"].as_str().unwrap());
            ml_dsa_call!(alg, deterministic_siggen_case(t));
            if unhex(&t["context"]).is_empty() {
                through_wrapper += 1;
                let vk_w = VerificationKey {
                    algorithm: alg,
                    bytes: unhex(&t["pk"]),
                };
                let sig_w = Signature {
                    algorithm: alg,
                    bytes: unhex(&t["signature"]),
                };
                let msg = unhex(&t["message"]);
                assert!(
                    sign::verify(&vk_w, &msg, &sig_w).unwrap(),
                    "tc {}: sign::verify",
                    t["tcId"]
                );
            }
        });
        assert_eq!((n, through_wrapper), (18, 5));
    }

    fn hedged_siggen_case<P: ml_dsa::MlDsaParams>(t: &Value) {
        let (sk, msg, ctx, rnd, sig) = (
            unhex(&t["sk"]),
            unhex(&t["message"]),
            unhex(&t["context"]),
            unhex(&t["rnd"]),
            unhex(&t["signature"]),
        );
        assert_eq!(rnd.len(), 32);
        let tc = &t["tcId"];
        let key = expanded_key::<P>(&sk);
        let mut rng = FixedRng(rnd);
        let s = key.sign_randomized(&msg, &ctx, &mut rng).unwrap();
        assert_eq!(s.encode().as_slice(), sig.as_slice(), "tc {tc}");
        assert!(rng.0.is_empty(), "tc {tc}: rnd not consumed");
    }

    /// sigGen, hedged, external interface, pure: `SigningKey::sign_randomized`, the call behind
    /// `sign::sign` and `sign::sign_randomized` for ML-DSA, returns NIST's signature when the
    /// random source yields NIST's rnd.
    #[test]
    fn ml_dsa_hedged_siggen_matches_acvp() {
        let file = load("ML-DSA-sigGen-FIPS204");
        let mut n = 0;
        each_test(&file, |g, t| {
            if g["deterministic"] != false {
                return;
            }
            n += 1;
            ml_dsa_call!(
                ml_dsa_alg(g["parameterSet"].as_str().unwrap()),
                hedged_siggen_case(t)
            );
        });
        assert_eq!(n, 12);
    }

    fn sigver_backend<P: ml_dsa::MlDsaParams>(t: &Value) -> bool {
        let (pk, msg, ctx, sig) = (
            unhex(&t["pk"]),
            unhex(&t["message"]),
            unhex(&t["context"]),
            unhex(&t["signature"]),
        );
        match ml_dsa::Signature::<P>::try_from(sig.as_slice()) {
            Ok(s) => decode_vk::<P>(&pk).verify_with_context(&msg, &ctx, &s),
            Err(_) => false,
        }
    }

    /// sigVer, external interface, pure: the backend accepts exactly the signatures NIST marks
    /// as valid (modified message, commitment, z and hint are all refused). Vectors with an
    /// empty context also go through `sign::verify`, which signs and verifies with an empty
    /// context: it must agree. With a non-empty context `sign::verify` must still never accept
    /// a signature NIST marks as invalid, and must not panic.
    #[test]
    fn ml_dsa_sigver_matches_acvp() {
        let file = load("ML-DSA-sigVer-FIPS204");
        let (mut n, mut through_wrapper) = (0, 0);
        each_test(&file, |g, t| {
            n += 1;
            let alg = ml_dsa_alg(g["parameterSet"].as_str().unwrap());
            let expected = t["testPassed"].as_bool().unwrap();
            let tc = &t["tcId"];
            let backend = ml_dsa_call!(alg, sigver_backend(t));
            assert_eq!(backend, expected, "tc {tc}: {}", t["reason"]);

            let wrapper = sign::verify(
                &VerificationKey {
                    algorithm: alg,
                    bytes: unhex(&t["pk"]),
                },
                &unhex(&t["message"]),
                &Signature {
                    algorithm: alg,
                    bytes: unhex(&t["signature"]),
                },
            );
            let accepted = matches!(wrapper, Ok(true));
            if unhex(&t["context"]).is_empty() {
                through_wrapper += 1;
                assert_eq!(accepted, expected, "tc {tc}: sign::verify, {}", t["reason"]);
            } else if !expected {
                assert!(
                    !accepted,
                    "tc {tc}: sign::verify accepted an invalid signature"
                );
            }
        });
        assert_eq!((n, through_wrapper), (18, 3));
    }

    // ── SLH-DSA ──

    fn slh_alg(set: &str) -> Option<SignAlgorithm> {
        match set {
            "SLH-DSA-SHAKE-128f" => Some(SignAlgorithm::SlhDsaShake128f),
            "SLH-DSA-SHAKE-256s" => Some(SignAlgorithm::SlhDsaShake256s),
            _ => None,
        }
    }

    /// keyGen: `slh_keygen_internal`, which `sign::keypair` calls with fresh seeds, rebuilds
    /// NIST's sk and pk, and the second half of sk is pk, which is how `sign::keypair` derives
    /// the verification key. A SHAKE-128f NIST key signs and verifies through the public API.
    #[test]
    fn slh_dsa_keygen_matches_acvp() {
        fn check<P: slh_dsa::ParameterSet>(t: &Value) -> Vec<u8> {
            let sk = slh_dsa::SigningKey::<P>::slh_keygen_internal(
                &unhex(&t["skSeed"]),
                &unhex(&t["skPrf"]),
                &unhex(&t["pkSeed"]),
            );
            let vk: &slh_dsa::VerifyingKey<P> = sk.as_ref();
            assert_eq!(vk.to_vec(), unhex(&t["pk"]), "tc {}: pk", t["tcId"]);
            sk.to_vec()
        }
        let file = load("SLH-DSA-keyGen-FIPS205");
        let mut wrapper = 0;
        let n = each_test(&file, |g, t| {
            let alg = slh_alg(g["parameterSet"].as_str().unwrap()).unwrap();
            let sk = match alg {
                SignAlgorithm::SlhDsaShake128f => check::<slh_dsa::Shake128f>(t),
                _ => check::<slh_dsa::Shake256s>(t),
            };
            let (nist_sk, nist_pk) = (unhex(&t["sk"]), unhex(&t["pk"]));
            assert_eq!(sk, nist_sk, "tc {}: sk", t["tcId"]);
            assert_eq!(
                &nist_sk[nist_sk.len() / 2..],
                nist_pk.as_slice(),
                "tc {}",
                t["tcId"]
            );
            if alg == SignAlgorithm::SlhDsaShake128f && wrapper < 2 {
                wrapper += 1;
                let sig = sign::sign(
                    &SigningKey {
                        algorithm: alg,
                        bytes: nist_sk,
                    },
                    b"acvp",
                )
                .unwrap();
                let vk = VerificationKey {
                    algorithm: alg,
                    bytes: nist_pk,
                };
                assert!(
                    sign::verify(&vk, b"acvp", &sig).unwrap(),
                    "tc {}",
                    t["tcId"]
                );
            }
        });
        assert_eq!((n, wrapper), (20, 2));
    }

    /// sigGen, deterministic, external interface, pure, for one parameter set. With an empty
    /// context the public `sign::sign` and `sign::sign_deterministic_dangerous` must return
    /// NIST's signature byte for byte; with any context, `try_sign_with_context` (what
    /// `sign::sign` calls, with an empty context) must.
    fn slh_dsa_siggen(set: &str) -> usize {
        fn backend<P: slh_dsa::ParameterSet>(sk: &[u8], msg: &[u8], ctx: &[u8]) -> Vec<u8> {
            let key = slh_dsa::SigningKey::<P>::try_from(sk).unwrap();
            key.try_sign_with_context(msg, ctx, None).unwrap().to_vec()
        }
        let file = load("SLH-DSA-sigGen-FIPS205");
        let mut n = 0;
        each_test(&file, |g, t| {
            if g["parameterSet"] != set {
                return;
            }
            n += 1;
            let alg = slh_alg(set).unwrap();
            let (pk, sk, msg, ctx, sig) = (
                unhex(&t["pk"]),
                unhex(&t["sk"]),
                unhex(&t["message"]),
                unhex(&t["context"]),
                unhex(&t["signature"]),
            );
            let tc = &t["tcId"];
            let got = match alg {
                SignAlgorithm::SlhDsaShake128f => backend::<slh_dsa::Shake128f>(&sk, &msg, &ctx),
                _ => backend::<slh_dsa::Shake256s>(&sk, &msg, &ctx),
            };
            assert_eq!(got, sig, "tc {tc}: backend");
            if ctx.is_empty() {
                let sk_w = SigningKey {
                    algorithm: alg,
                    bytes: sk,
                };
                assert_eq!(
                    sign::sign(&sk_w, &msg).unwrap().bytes,
                    sig,
                    "tc {tc}: sign::sign"
                );
                let det = sign::sign_deterministic_dangerous(&sk_w, &msg).unwrap();
                assert_eq!(det.bytes, sig, "tc {tc}: sign_deterministic_dangerous");
                let vk_w = VerificationKey {
                    algorithm: alg,
                    bytes: pk,
                };
                assert!(
                    sign::verify(&vk_w, &msg, &det).unwrap(),
                    "tc {tc}: sign::verify"
                );
            }
        });
        n
    }

    #[test]
    fn slh_dsa_shake_128f_siggen_matches_acvp() {
        assert_eq!(slh_dsa_siggen("SLH-DSA-SHAKE-128f"), 3);
    }

    #[test]
    #[ignore = "minutes in a debug build; run with --release -- --ignored"]
    fn slh_dsa_shake_256s_siggen_matches_acvp() {
        assert_eq!(slh_dsa_siggen("SLH-DSA-SHAKE-256s"), 3);
    }

    /// sigVer, external interface, pure: the backend accepts exactly NIST's valid signatures
    /// (modified R, SIGFORS, SIGHT and message are refused, and so are signatures one byte too
    /// long or too short). Empty-context vectors also go through `sign::verify`; with any
    /// context, `sign::verify` must not accept an invalid signature or panic.
    #[test]
    fn slh_dsa_sigver_matches_acvp() {
        fn backend<P: slh_dsa::ParameterSet>(
            pk: &[u8],
            msg: &[u8],
            ctx: &[u8],
            sig: &[u8],
        ) -> bool {
            let vk = slh_dsa::VerifyingKey::<P>::try_from(pk).unwrap();
            match slh_dsa::Signature::<P>::try_from(sig) {
                Ok(s) => vk.try_verify_with_context(msg, ctx, &s).is_ok(),
                Err(_) => false,
            }
        }
        let file = load("SLH-DSA-sigVer-FIPS205");
        let (mut n, mut through_wrapper) = (0, 0);
        each_test(&file, |g, t| {
            n += 1;
            let alg = slh_alg(g["parameterSet"].as_str().unwrap()).unwrap();
            let (pk, msg, ctx, sig) = (
                unhex(&t["pk"]),
                unhex(&t["message"]),
                unhex(&t["context"]),
                unhex(&t["signature"]),
            );
            let expected = t["testPassed"].as_bool().unwrap();
            let tc = &t["tcId"];
            let got = match alg {
                SignAlgorithm::SlhDsaShake128f => {
                    backend::<slh_dsa::Shake128f>(&pk, &msg, &ctx, &sig)
                }
                _ => backend::<slh_dsa::Shake256s>(&pk, &msg, &ctx, &sig),
            };
            assert_eq!(got, expected, "tc {tc}: {}", t["reason"]);

            let wrapper = sign::verify(
                &VerificationKey {
                    algorithm: alg,
                    bytes: pk,
                },
                &msg,
                &Signature {
                    algorithm: alg,
                    bytes: sig,
                },
            );
            let accepted = matches!(wrapper, Ok(true));
            if ctx.is_empty() {
                through_wrapper += 1;
                assert_eq!(accepted, expected, "tc {tc}: sign::verify, {}", t["reason"]);
            } else if !expected {
                assert!(
                    !accepted,
                    "tc {tc}: sign::verify accepted an invalid signature"
                );
            }
        });
        assert_eq!((n, through_wrapper), (14, 2));
    }
}
