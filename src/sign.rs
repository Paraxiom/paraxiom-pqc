//! Digital signatures: ML-DSA (FIPS 204), SLH-DSA (FIPS 205) and Falcon (FIPS 206, still a
//! draft).
//!
//! Pure Rust. Zero C.
//!
//! Signing keys are cleared from memory when dropped. Falcon key generation and signing are
//! built only on targets where they run on hardware floating point; see
//! [`FALCON_SIGNING_AVAILABLE`].

use crate::PqcError;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaShake128f,
    SlhDsaShake256s,
    Falcon512,
    Falcon1024,
}

/// Signing key (secret).
///
/// `bytes` is cleared when the key is dropped. Because of that `Drop` impl, `bytes` cannot be
/// moved out of the key; borrow it, clone it, or take it with `std::mem::take(&mut sk.bytes)`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKey {
    #[zeroize(skip)]
    pub algorithm: SignAlgorithm,
    pub bytes: Vec<u8>,
}
#[derive(Clone)]
pub struct VerificationKey {
    pub algorithm: SignAlgorithm,
    pub bytes: Vec<u8>,
}
pub struct Signature {
    pub algorithm: SignAlgorithm,
    pub bytes: Vec<u8>,
}
pub struct SignKeypair {
    pub vk: VerificationKey,
    pub sk: SigningKey,
}

pub fn keypair(alg: SignAlgorithm) -> Result<SignKeypair, PqcError> {
    match alg {
        SignAlgorithm::MlDsa44 => ml_dsa_keygen::<ml_dsa::MlDsa44>(alg, &*random_seed()?),
        SignAlgorithm::MlDsa65 => ml_dsa_keygen::<ml_dsa::MlDsa65>(alg, &*random_seed()?),
        SignAlgorithm::MlDsa87 => ml_dsa_keygen::<ml_dsa::MlDsa87>(alg, &*random_seed()?),
        SignAlgorithm::SlhDsaShake128f => slh_dsa_keygen::<slh_dsa::Shake128f>(alg, 16),
        SignAlgorithm::SlhDsaShake256s => slh_dsa_keygen::<slh_dsa::Shake256s>(alg, 32),
        SignAlgorithm::Falcon512 => falcon_keygen(9, alg),
        SignAlgorithm::Falcon1024 => falcon_keygen(10, alg),
    }
}

/// Generate a signing keypair seeded from a quantum entropy source (feature
/// `qrng`, default OFF).
///
/// The QRNG seeds a SHAKE256-conditioned CSPRNG ([`crate::qrng::QrngRng`]); see
/// that module for the honesty/scope notes (entropy-source *assurance*, not a
/// stronger-crypto claim). Currently wired for ML-DSA (the seed-based FIPS 204
/// path); SLH-DSA and Falcon return an explicit error until their keygen RNG is
/// parameterised.
#[cfg(feature = "qrng")]
pub fn keypair_qrng<S: crate::qrng::QuantumSource>(
    alg: SignAlgorithm,
    qrng: &mut crate::qrng::QrngRng<S>,
) -> Result<SignKeypair, PqcError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    match alg {
        SignAlgorithm::MlDsa44 => {
            qrng.fill(&mut *seed);
            ml_dsa_keygen::<ml_dsa::MlDsa44>(alg, &seed)
        }
        SignAlgorithm::MlDsa65 => {
            qrng.fill(&mut *seed);
            ml_dsa_keygen::<ml_dsa::MlDsa65>(alg, &seed)
        }
        SignAlgorithm::MlDsa87 => {
            qrng.fill(&mut *seed);
            ml_dsa_keygen::<ml_dsa::MlDsa87>(alg, &seed)
        }
        _ => Err(PqcError::KeyGen(
            "QRNG-seeded keygen is currently wired for ML-DSA only".into(),
        )),
    }
}

/// Sign a message.
///
/// ML-DSA signs in the hedged (randomized) mode of FIPS 204, through upstream ml-dsa's
/// variable-length rejection loop, with fresh OS randomness for every signature. Hedged signatures
/// are standard FIPS 204 signatures. This has been the default since 2026-08-19, after the timing
/// measurements in `docs/SIDE-CHANNEL-AUDIT.md` (dudect, Welch's t-test, about 10^4 samples per
/// class, threshold |t| 4.5): upstream's deterministic loop gave each key its own signing time
/// (|t| 112.8 on x86-64 and 98.7 on a Cortex-A53), while hedged signing measured |t| 4.4 and 1.5.
/// That is below the threshold, not proof of constant time: |t| 4.4 is close to it, and the
/// expected number of rounds still depends on the key.
///
/// SLH-DSA signs deterministically. Falcon is randomized by construction, and is built only on
/// some targets: see [`FALCON_SIGNING_AVAILABLE`].
///
/// If a protocol requires deterministic ML-DSA signatures, use [`sign_deterministic_dangerous`]
/// and read its warning first.
pub fn sign(sk: &SigningKey, msg: &[u8]) -> Result<Signature, PqcError> {
    match sk.algorithm {
        SignAlgorithm::MlDsa44 => ml_dsa_sign_randomized::<ml_dsa::MlDsa44>(sk, msg),
        SignAlgorithm::MlDsa65 => ml_dsa_sign_randomized::<ml_dsa::MlDsa65>(sk, msg),
        SignAlgorithm::MlDsa87 => ml_dsa_sign_randomized::<ml_dsa::MlDsa87>(sk, msg),
        SignAlgorithm::SlhDsaShake128f => slh_dsa_sign::<slh_dsa::Shake128f>(sk, msg),
        SignAlgorithm::SlhDsaShake256s => slh_dsa_sign::<slh_dsa::Shake256s>(sk, msg),
        SignAlgorithm::Falcon512 | SignAlgorithm::Falcon1024 => falcon_sign(sk, msg),
    }
}

/// Deterministic ML-DSA signing. Read this before using it.
///
/// For ML-DSA this runs the fixed-round kernel (`src/dsa_ct.rs`, implemented in the vendored
/// ml-dsa fork): 814 rounds of the signing loop every time, the lowest loop limit FIPS 204
/// allows, keeping the first candidate that passes the checks. The result is the standard
/// deterministic FIPS 204 signature. Its limits:
///
/// - Its timing has never been measured. The deterministic leak quoted under [`sign`] was
///   measured on upstream's variable-length loop before this kernel existed (2026-07-12). No
///   published figure describes the kernel. `cargo run --release --example dudect_timing`
///   measures it.
/// - It is not fully constant time: the round that accepts takes a branch the other rounds skip.
/// - It is slow: 814 rounds where [`sign`] runs 3.85 to 5.1 on average.
/// - With probability about 2^-315, 2^-256 and 2^-353 (ML-DSA-44, -65, -87) every round rejects
///   and this returns an error.
///
/// Use it only when a protocol requires deterministic signatures and the signer cannot be timed
/// by an adversary (no co-located processes, no remote timing, no physical access). Otherwise use
/// [`sign`]. Other algorithms delegate to [`sign`].
pub fn sign_deterministic_dangerous(sk: &SigningKey, msg: &[u8]) -> Result<Signature, PqcError> {
    match sk.algorithm {
        SignAlgorithm::MlDsa44 => ml_dsa_sign::<ml_dsa::MlDsa44>(sk, msg),
        SignAlgorithm::MlDsa65 => ml_dsa_sign::<ml_dsa::MlDsa65>(sk, msg),
        SignAlgorithm::MlDsa87 => ml_dsa_sign::<ml_dsa::MlDsa87>(sk, msg),
        _ => sign(sk, msg),
    }
}

/// Hedged (randomized) signing. For ML-DSA this is what [`sign`] has done since 2026-08-19; the
/// function stays for compatibility and to make the choice explicit. Other algorithms delegate
/// to [`sign`].
pub fn sign_randomized(sk: &SigningKey, msg: &[u8]) -> Result<Signature, PqcError> {
    match sk.algorithm {
        SignAlgorithm::MlDsa44 => ml_dsa_sign_randomized::<ml_dsa::MlDsa44>(sk, msg),
        SignAlgorithm::MlDsa65 => ml_dsa_sign_randomized::<ml_dsa::MlDsa65>(sk, msg),
        SignAlgorithm::MlDsa87 => ml_dsa_sign_randomized::<ml_dsa::MlDsa87>(sk, msg),
        _ => sign(sk, msg),
    }
}

/// OS-entropy RNG (getrandom-backed) for hedged signing. Implementing `TryRng`
/// with `Error = Infallible` yields `Rng`/`CryptoRng`/`TryCryptoRng` via
/// rand_core 0.10's blanket impls.
struct OsGetRandom;
impl rand_core::TryRng for OsGetRandom {
    type Error = rand_core::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("getrandom");
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).expect("getrandom");
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).expect("getrandom");
        Ok(())
    }
}
impl rand_core::TryCryptoRng for OsGetRandom {}

/// Rebuilds the backend ML-DSA key from the 32-byte seed in `sk`. The seed is borrowed, the
/// one array copy is cleared on return, and the backend key clears itself on drop.
fn ml_dsa_signing_key<P: ml_dsa::MlDsaParams>(
    sk: &SigningKey,
) -> Result<ml_dsa::SigningKey<P>, PqcError> {
    let seed: &[u8; 32] = sk
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| PqcError::Sign("invalid seed size".into()))?;
    let b32 = Zeroizing::new(ml_dsa::B32::from(*seed));
    Ok(ml_dsa::SigningKey::<P>::from_seed(&b32))
}

fn ml_dsa_sign_randomized<P: ml_dsa::MlDsaParams>(
    sk: &SigningKey,
    msg: &[u8],
) -> Result<Signature, PqcError> {
    let signing_key = ml_dsa_signing_key::<P>(sk)?;
    let mut rng = OsGetRandom;
    let sig = signing_key
        .sign_randomized(msg, b"", &mut rng)
        .map_err(|e| PqcError::Sign(format!("{:?}", e)))?;
    Ok(Signature {
        algorithm: sk.algorithm,
        bytes: sig.encode().to_vec(),
    })
}

pub fn verify(vk: &VerificationKey, msg: &[u8], sig: &Signature) -> Result<bool, PqcError> {
    match vk.algorithm {
        SignAlgorithm::MlDsa44 => ml_dsa_verify::<ml_dsa::MlDsa44>(vk, msg, sig),
        SignAlgorithm::MlDsa65 => ml_dsa_verify::<ml_dsa::MlDsa65>(vk, msg, sig),
        SignAlgorithm::MlDsa87 => ml_dsa_verify::<ml_dsa::MlDsa87>(vk, msg, sig),
        SignAlgorithm::SlhDsaShake128f => slh_dsa_verify::<slh_dsa::Shake128f>(vk, msg, sig),
        SignAlgorithm::SlhDsaShake256s => slh_dsa_verify::<slh_dsa::Shake256s>(vk, msg, sig),
        SignAlgorithm::Falcon512 | SignAlgorithm::Falcon1024 => falcon_verify(vk, msg, sig),
    }
}

// ── ML-DSA (FIPS 204) ──────────────────────────────────────────────────────

fn random_seed() -> Result<Zeroizing<[u8; 32]>, PqcError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|e| PqcError::KeyGen(format!("{:?}", e)))?;
    Ok(seed)
}

fn ml_dsa_keygen<P: ml_dsa::MlDsaParams + ml_dsa::KeyGen>(
    alg: SignAlgorithm,
    seed: &[u8; 32],
) -> Result<SignKeypair, PqcError> {
    let b32 = Zeroizing::new(ml_dsa::B32::from(*seed));
    let sk = ml_dsa::SigningKey::<P>::from_seed(&b32);
    let vk_enc = sk.verifying_key().encode();
    Ok(SignKeypair {
        sk: SigningKey {
            algorithm: alg,
            bytes: seed.to_vec(),
        },
        vk: VerificationKey {
            algorithm: alg,
            bytes: vk_enc.to_vec(),
        },
    })
}

fn ml_dsa_sign<P: ml_dsa::MlDsaParams>(sk: &SigningKey, msg: &[u8]) -> Result<Signature, PqcError> {
    let signing_key = ml_dsa_signing_key::<P>(sk)?;
    let sig = crate::dsa_ct::sign_constant_time(&signing_key, msg, b"")
        .map_err(|e| PqcError::Sign(format!("{:?}", e)))?;
    Ok(Signature {
        algorithm: sk.algorithm,
        bytes: sig.encode().to_vec(),
    })
}

fn ml_dsa_verify<P: ml_dsa::MlDsaParams>(
    vk: &VerificationKey,
    msg: &[u8],
    sig: &Signature,
) -> Result<bool, PqcError> {
    // Reconstruct VK from encoded bytes
    let vk_bytes: &[u8] = &vk.bytes;
    // Use verify_internal which takes raw signature bytes
    let enc_sig = ml_dsa::EncodedSignature::<P>::try_from(sig.bytes.as_slice())
        .map_err(|_| PqcError::Verify("invalid signature size".into()))?;
    let decoded_sig = ml_dsa::Signature::<P>::decode(&enc_sig)
        .ok_or_else(|| PqcError::Verify("signature decode failed".into()))?;

    // Build VK from encoded bytes
    let enc_vk = ml_dsa::EncodedVerifyingKey::<P>::try_from(vk_bytes)
        .map_err(|_| PqcError::Verify("invalid verifying key size".into()))?;
    let verifying_key = ml_dsa::VerifyingKey::<P>::decode(&enc_vk);
    Ok(verifying_key.verify_with_context(msg, b"", &decoded_sig))
}

// ── SLH-DSA (FIPS 205) ─────────────────────────────────────────────────────

fn slh_dsa_keygen<P: slh_dsa::ParameterSet>(
    alg: SignAlgorithm,
    n: usize,
) -> Result<SignKeypair, PqcError> {
    // Generate 3*N random bytes for sk_seed, sk_prf, pk_seed. The buffer is cleared on drop;
    // the backend key clears itself too, and its encoding moves into our SigningKey.
    let mut seed = Zeroizing::new(vec![0u8; 3 * n]);
    getrandom::fill(seed.as_mut_slice()).map_err(|e| PqcError::KeyGen(format!("{:?}", e)))?;
    let sk =
        slh_dsa::SigningKey::<P>::slh_keygen_internal(&seed[..n], &seed[n..2 * n], &seed[2 * n..]);
    let sk_bytes = sk.to_vec();
    let vk_bytes = sk_bytes[sk_bytes.len() / 2..].to_vec();
    Ok(SignKeypair {
        sk: SigningKey {
            algorithm: alg,
            bytes: sk_bytes,
        },
        vk: VerificationKey {
            algorithm: alg,
            bytes: vk_bytes,
        },
    })
}

fn slh_dsa_sign<P: slh_dsa::ParameterSet>(
    sk: &SigningKey,
    msg: &[u8],
) -> Result<Signature, PqcError> {
    let signing_key = slh_dsa::SigningKey::<P>::try_from(sk.bytes.as_slice())
        .map_err(|_| PqcError::Sign("invalid signing key".into()))?;
    let sig = signing_key
        .try_sign_with_context(msg, b"", None)
        .map_err(|e| PqcError::Sign(format!("{:?}", e)))?;
    Ok(Signature {
        algorithm: sk.algorithm,
        bytes: sig.to_vec(),
    })
}

fn slh_dsa_verify<P: slh_dsa::ParameterSet>(
    vk: &VerificationKey,
    msg: &[u8],
    sig: &Signature,
) -> Result<bool, PqcError> {
    let verifying_key = slh_dsa::VerifyingKey::<P>::try_from(vk.bytes.as_slice())
        .map_err(|_| PqcError::Verify("invalid verifying key".into()))?;
    let signature = slh_dsa::Signature::<P>::try_from(sig.bytes.as_slice())
        .map_err(|_| PqcError::Verify("invalid signature".into()))?;
    match verifying_key.try_verify_with_context(msg, b"", &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ── Falcon (pending FIPS 206) ───────────────────────────────────────────────

/// `true` when Falcon key generation and signing are built for this target.
///
/// falcon-rs 0.2.3 computes key generation and signing in native `f64` on secret values
/// (`src/fpr.rs`) and takes square roots of secret values with `libm::sqrt`. All of it runs as
/// hardware instructions on two families of targets only: x86 and x86_64 with SSE2, and AArch64
/// with NEON. There the compiler emits FPU instructions for `f64`, and libm 0.2 uses the hardware
/// square root. On any other target part of it runs in software: the compiler's soft-float
/// routines where there is no FPU, and libm's table-based square root everywhere else. Those
/// routines take a time that depends on their operands, which are secret here, and falcon-rs
/// itself does not refuse such a target.
///
/// On those other targets this is `false`. The Falcon key generation and signing code is then not
/// compiled, and [`keypair`], [`sign`], [`sign_randomized`] and [`sign_deterministic_dangerous`]
/// return an error for Falcon. Verification uses integer arithmetic only and works on every
/// target. A crate that needs Falcon signing can turn a wrong target into a build error:
///
/// ```
/// const _: () = assert!(
///     paraxiom_pqc::sign::FALCON_SIGNING_AVAILABLE,
///     "Falcon signing needs x86/x86_64 with SSE2 or AArch64 with NEON"
/// );
/// ```
///
/// The guard only rules out software floating point. It does not show that Falcon signing is
/// constant time where it is allowed: the only timing data is a mean-timing (dudect) run on
/// Falcon-512 (`docs/SIDE-CHANNEL-AUDIT.md`), and on some x86 processors the division and
/// square root instructions have operand-dependent latency.
pub const FALCON_SIGNING_AVAILABLE: bool = falcon_secret::AVAILABLE;

// Falcon key generation and signing. The condition is libm 0.2's own condition for using the
// hardware square root, restricted to targets where `f64` arithmetic is hardware as well.
#[cfg(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2"
    ),
    all(target_arch = "aarch64", target_feature = "neon"),
))]
mod falcon_secret {
    use super::{SignAlgorithm, SignKeypair, Signature, SigningKey, VerificationKey};
    use crate::PqcError;
    use falcon::safe_api::{DomainSeparation, FnDsaKeyPair};

    pub(super) const AVAILABLE: bool = true;

    pub(super) fn keygen(logn: u32, alg: SignAlgorithm) -> Result<SignKeypair, PqcError> {
        let kp = FnDsaKeyPair::generate(logn).map_err(|e| PqcError::KeyGen(format!("{:?}", e)))?;
        Ok(SignKeypair {
            sk: SigningKey {
                algorithm: alg,
                bytes: kp.private_key().to_vec(),
            },
            vk: VerificationKey {
                algorithm: alg,
                bytes: kp.public_key().to_vec(),
            },
        })
    }

    pub(super) fn sign(sk: &SigningKey, msg: &[u8]) -> Result<Signature, PqcError> {
        let kp = FnDsaKeyPair::from_private_key(&sk.bytes)
            .map_err(|e| PqcError::Sign(format!("{:?}", e)))?;
        let sig = kp
            .sign(msg, &DomainSeparation::None)
            .map_err(|e| PqcError::Sign(format!("{:?}", e)))?;
        Ok(Signature {
            algorithm: sk.algorithm,
            bytes: sig.to_bytes().to_vec(),
        })
    }
}

// Every other target: no Falcon secret-key code is compiled, and both operations refuse.
#[cfg(not(any(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse2"
    ),
    all(target_arch = "aarch64", target_feature = "neon"),
)))]
mod falcon_secret {
    use super::{falcon_refusal, SignAlgorithm, SignKeypair, Signature, SigningKey};
    use crate::PqcError;

    pub(super) const AVAILABLE: bool = false;

    pub(super) fn keygen(_logn: u32, _alg: SignAlgorithm) -> Result<SignKeypair, PqcError> {
        Err(PqcError::KeyGen(falcon_refusal("key generation")))
    }

    pub(super) fn sign(_sk: &SigningKey, _msg: &[u8]) -> Result<Signature, PqcError> {
        Err(PqcError::Sign(falcon_refusal("signing")))
    }
}

/// Error text for Falcon key generation or signing on a target where they are not built.
// Called by the refusing module, which exists only on such targets, and by the tests.
#[allow(dead_code)]
fn falcon_refusal(operation: &str) -> String {
    format!(
        "Falcon {operation} is not built for this target ({arch}): falcon-rs computes on secret \
         values in floating point, and only x86/x86_64 with SSE2 and AArch64 with NEON run all \
         of it in hardware. Use ML-DSA or SLH-DSA on this target; Falcon verification still \
         works (see paraxiom_pqc::sign::FALCON_SIGNING_AVAILABLE)",
        arch = std::env::consts::ARCH
    )
}

fn falcon_keygen(logn: u32, alg: SignAlgorithm) -> Result<SignKeypair, PqcError> {
    falcon_secret::keygen(logn, alg)
}

fn falcon_sign(sk: &SigningKey, msg: &[u8]) -> Result<Signature, PqcError> {
    falcon_secret::sign(sk, msg)
}

fn falcon_verify(vk: &VerificationKey, msg: &[u8], sig: &Signature) -> Result<bool, PqcError> {
    Ok(crate::falcon::verify(&vk.bytes, msg, &sig.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_44() {
        let kp = keypair(SignAlgorithm::MlDsa44).unwrap();
        let sig = sign(&kp.sk, b"FIPS 204").unwrap();
        assert!(verify(&kp.vk, b"FIPS 204", &sig).unwrap());
    }
    #[test]
    fn test_ml_dsa_65() {
        let kp = keypair(SignAlgorithm::MlDsa65).unwrap();
        let sig = sign(&kp.sk, b"ML-DSA-65").unwrap();
        assert!(verify(&kp.vk, b"ML-DSA-65", &sig).unwrap());
    }
    #[test]
    fn test_ml_dsa_87() {
        let kp = keypair(SignAlgorithm::MlDsa87).unwrap();
        let sig = sign(&kp.sk, b"ML-DSA-87").unwrap();
        assert!(verify(&kp.vk, b"ML-DSA-87", &sig).unwrap());
    }
    #[test]
    fn test_ml_dsa_tampered() {
        let kp = keypair(SignAlgorithm::MlDsa65).unwrap();
        let sig = sign(&kp.sk, b"original").unwrap();
        assert!(!verify(&kp.vk, b"tampered", &sig).unwrap());
    }
    #[test]
    fn test_slh_dsa_shake_128f() {
        let kp = keypair(SignAlgorithm::SlhDsaShake128f).unwrap();
        let sig = sign(&kp.sk, b"FIPS 205").unwrap();
        assert!(verify(&kp.vk, b"FIPS 205", &sig).unwrap());
    }
    #[test]
    fn test_slh_dsa_shake_256s() {
        let kp = keypair(SignAlgorithm::SlhDsaShake256s).unwrap();
        let sig = sign(&kp.sk, b"SLH-DSA-256s").unwrap();
        assert!(verify(&kp.vk, b"SLH-DSA-256s", &sig).unwrap());
    }
    #[test]
    fn test_slh_dsa_tampered() {
        let kp = keypair(SignAlgorithm::SlhDsaShake128f).unwrap();
        let sig = sign(&kp.sk, b"original").unwrap();
        assert!(!verify(&kp.vk, b"tampered", &sig).unwrap());
    }
    // The three Falcon round trips need key generation and signing, which exist only where
    // FALCON_SIGNING_AVAILABLE holds; falcon_secret_key_operations_follow_the_guard covers the
    // other targets.
    #[test]
    fn test_falcon512() {
        if !FALCON_SIGNING_AVAILABLE {
            return;
        }
        let kp = keypair(SignAlgorithm::Falcon512).unwrap();
        let sig = sign(&kp.sk, b"Falcon-512").unwrap();
        assert!(verify(&kp.vk, b"Falcon-512", &sig).unwrap());
    }
    #[test]
    fn test_falcon1024() {
        if !FALCON_SIGNING_AVAILABLE {
            return;
        }
        let kp = keypair(SignAlgorithm::Falcon1024).unwrap();
        let sig = sign(&kp.sk, b"Falcon-1024").unwrap();
        assert!(verify(&kp.vk, b"Falcon-1024", &sig).unwrap());
    }
    #[test]
    fn test_falcon_tampered() {
        if !FALCON_SIGNING_AVAILABLE {
            return;
        }
        let kp = keypair(SignAlgorithm::Falcon512).unwrap();
        let sig = sign(&kp.sk, b"original").unwrap();
        assert!(!verify(&kp.vk, b"tampered", &sig).unwrap());
    }

    // ── Falcon target guard ─────────────────────────────────────────────────

    /// The guard holds exactly on x86/x86_64 with SSE2 and on AArch64 with NEON. This restates
    /// the condition independently of the cfg attributes on the two `falcon_secret` modules.
    #[test]
    fn falcon_signing_available_only_with_hardware_float() {
        let expected = (cfg!(any(target_arch = "x86", target_arch = "x86_64"))
            && cfg!(target_feature = "sse2"))
            || (cfg!(target_arch = "aarch64") && cfg!(target_feature = "neon"));
        assert_eq!(FALCON_SIGNING_AVAILABLE, expected);
    }

    /// Where the guard allows Falcon, key generation and signing work. Elsewhere every
    /// secret-key entry point refuses with the guard's error, including a key made elsewhere.
    /// Verification is covered on every target by tests/falcon_verify.rs.
    #[test]
    fn falcon_secret_key_operations_follow_the_guard() {
        for (alg, sk_len) in [
            (SignAlgorithm::Falcon512, 1281),
            (SignAlgorithm::Falcon1024, 2305),
        ] {
            let generated = keypair(alg);
            if FALCON_SIGNING_AVAILABLE {
                let kp = generated.unwrap();
                assert_eq!(kp.sk.bytes.len(), sk_len);
                for sig in [
                    sign(&kp.sk, b"guard").unwrap(),
                    sign_randomized(&kp.sk, b"guard").unwrap(),
                    sign_deterministic_dangerous(&kp.sk, b"guard").unwrap(),
                ] {
                    assert!(verify(&kp.vk, b"guard", &sig).unwrap());
                }
            } else {
                let refused = |e: Option<PqcError>| {
                    e.expect("Falcon must be refused on this target")
                        .to_string()
                        .contains("not built for this target")
                };
                assert!(refused(generated.err()));
                let foreign = SigningKey {
                    algorithm: alg,
                    bytes: vec![0x50 | if sk_len == 1281 { 9 } else { 10 }; sk_len],
                };
                assert!(refused(sign(&foreign, b"guard").err()));
                assert!(refused(sign_randomized(&foreign, b"guard").err()));
                assert!(refused(
                    sign_deterministic_dangerous(&foreign, b"guard").err()
                ));
            }
        }
    }

    /// The refusal names the reason, the allowed targets and the way out.
    #[test]
    fn falcon_refusal_explains_itself() {
        let text = falcon_refusal("signing");
        assert!(text.starts_with("Falcon signing is not built for this target"));
        assert!(text.contains(std::env::consts::ARCH));
        assert!(text.contains("SSE2") && text.contains("NEON"));
        assert!(text.contains("Use ML-DSA or SLH-DSA"));
        assert!(text.contains("verification still works"));
    }

    // ── ML-DSA deterministic-mode fence (after the timing measurements, 2026-08-19) ─

    /// The default `sign` MUST be hedged for ML-DSA: two signatures over the
    /// same (key, msg) differ (fresh per-signature randomness), and both verify.
    #[test]
    fn ml_dsa_default_sign_is_hedged() {
        let kp = keypair(SignAlgorithm::MlDsa44).unwrap();
        let s1 = sign(&kp.sk, b"audit msg").unwrap();
        let s2 = sign(&kp.sk, b"audit msg").unwrap();
        assert_ne!(
            s1.bytes, s2.bytes,
            "default ML-DSA signing must be hedged (randomized), not deterministic"
        );
        assert!(verify(&kp.vk, b"audit msg", &s1).unwrap());
        assert!(verify(&kp.vk, b"audit msg", &s2).unwrap());
    }

    /// The fenced deterministic path still works and is byte-stable, for the
    /// rare protocol that requires it (and accepts the limits in its docs).
    #[test]
    fn ml_dsa_deterministic_dangerous_is_stable_and_valid() {
        let kp = keypair(SignAlgorithm::MlDsa44).unwrap();
        let s1 = sign_deterministic_dangerous(&kp.sk, b"audit msg").unwrap();
        let s2 = sign_deterministic_dangerous(&kp.sk, b"audit msg").unwrap();
        assert_eq!(s1.bytes, s2.bytes, "deterministic mode must be byte-stable");
        assert!(verify(&kp.vk, b"audit msg", &s1).unwrap());
    }

    /// Non-ML-DSA algorithms delegate through the fence unchanged.
    #[test]
    fn deterministic_dangerous_delegates_for_non_ml_dsa() {
        let kp = keypair(SignAlgorithm::SlhDsaShake128f).unwrap();
        let sig = sign_deterministic_dangerous(&kp.sk, b"delegate").unwrap();
        assert!(verify(&kp.vk, b"delegate", &sig).unwrap());
    }

    // ── Zeroization ─────────────────────────────────────────────────────────

    fn zeroize_on_drop<T: ZeroizeOnDrop>() {}

    /// Compile-time check: our signing key and every backend key the signing paths build
    /// clear themselves on drop. Fails to build if the derive or a backend `zeroize` feature
    /// is removed. falcon-rs keeps its private key in `Zeroizing` unconditionally.
    /// tests/zeroize.rs checks the heap buffers themselves.
    #[test]
    fn secret_types_zeroize_on_drop() {
        zeroize_on_drop::<SigningKey>();
        zeroize_on_drop::<ml_dsa::SigningKey<ml_dsa::MlDsa44>>();
        zeroize_on_drop::<ml_dsa::SigningKey<ml_dsa::MlDsa65>>();
        zeroize_on_drop::<ml_dsa::SigningKey<ml_dsa::MlDsa87>>();
        zeroize_on_drop::<ml_dsa::KeyPair<ml_dsa::MlDsa65>>();
        zeroize_on_drop::<slh_dsa::SigningKey<slh_dsa::Shake128f>>();
        zeroize_on_drop::<slh_dsa::SigningKey<slh_dsa::Shake256s>>();
    }

    #[test]
    fn zeroize_clears_signing_key_bytes() {
        let mut kp = keypair(SignAlgorithm::MlDsa65).unwrap();
        assert_eq!(kp.sk.bytes.len(), 32);
        kp.sk.zeroize();
        assert!(kp.sk.bytes.is_empty());
        assert_eq!(kp.sk.algorithm, SignAlgorithm::MlDsa65);
    }
}
