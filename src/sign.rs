//! Digital Signatures — ML-DSA (FIPS 204), SLH-DSA (FIPS 205), Falcon (FIPS 206)
//!
//! Pure Rust. Zero C.

use crate::PqcError;

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

pub struct SigningKey {
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
        SignAlgorithm::MlDsa44 => ml_dsa_keygen::<ml_dsa::MlDsa44>(alg),
        SignAlgorithm::MlDsa65 => ml_dsa_keygen::<ml_dsa::MlDsa65>(alg),
        SignAlgorithm::MlDsa87 => ml_dsa_keygen::<ml_dsa::MlDsa87>(alg),
        SignAlgorithm::SlhDsaShake128f => slh_dsa_keygen::<slh_dsa::Shake128f>(alg, 16),
        SignAlgorithm::SlhDsaShake256s => slh_dsa_keygen::<slh_dsa::Shake256s>(alg, 32),
        SignAlgorithm::Falcon512 => falcon_keygen(9, alg),
        SignAlgorithm::Falcon1024 => falcon_keygen(10, alg),
    }
}

pub fn sign(sk: &SigningKey, msg: &[u8]) -> Result<Signature, PqcError> {
    match sk.algorithm {
        SignAlgorithm::MlDsa44 => ml_dsa_sign::<ml_dsa::MlDsa44>(sk, msg),
        SignAlgorithm::MlDsa65 => ml_dsa_sign::<ml_dsa::MlDsa65>(sk, msg),
        SignAlgorithm::MlDsa87 => ml_dsa_sign::<ml_dsa::MlDsa87>(sk, msg),
        SignAlgorithm::SlhDsaShake128f => slh_dsa_sign::<slh_dsa::Shake128f>(sk, msg),
        SignAlgorithm::SlhDsaShake256s => slh_dsa_sign::<slh_dsa::Shake256s>(sk, msg),
        SignAlgorithm::Falcon512 | SignAlgorithm::Falcon1024 => falcon_sign(sk, msg),
    }
}

/// Randomized (hedged) signing. For ML-DSA this draws fresh per-signature
/// randomness (FIPS 204 §3.4 hedged variant), which removes the stable per-key
/// signing-time fingerprint that *deterministic* ML-DSA exposes via its
/// rejection-sampling loop (see `examples/dudect_timing.rs`). Falcon is already
/// randomized and SLH-DSA-*f is timing-flat, so those fall back to `sign`.
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

fn ml_dsa_sign_randomized<P: ml_dsa::MlDsaParams>(
    sk: &SigningKey,
    msg: &[u8],
) -> Result<Signature, PqcError> {
    let seed: [u8; 32] = sk
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| PqcError::Sign("invalid seed size".into()))?;
    let b32 = ml_dsa::B32::from(seed);
    let signing_key = ml_dsa::SigningKey::<P>::from_seed(&b32);
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

fn random_seed() -> Result<[u8; 32], PqcError> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| PqcError::KeyGen(format!("{:?}", e)))?;
    Ok(seed)
}

fn ml_dsa_keygen<P: ml_dsa::MlDsaParams + ml_dsa::KeyGen>(
    alg: SignAlgorithm,
) -> Result<SignKeypair, PqcError> {
    let seed = random_seed()?;
    let b32 = ml_dsa::B32::from(seed);
    // Original `P::from_seed(&b32)` is kept commented for context: it
    // pulls VK encoding via the trait method, but we need the raw
    // `SigningKey<P>` for the trait-method `verifying_key()` call below.
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
    let seed: [u8; 32] = sk
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| PqcError::Sign("invalid seed size".into()))?;
    let b32 = ml_dsa::B32::from(seed);
    let signing_key = ml_dsa::SigningKey::<P>::from_seed(&b32);
    let sig = signing_key
        .sign_deterministic(msg, b"")
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
    let _signing_seed_dummy = random_seed().map_err(|e| PqcError::Verify(format!("{:?}", e)))?;
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
    // Generate 3*N random bytes for sk_seed, sk_prf, pk_seed
    let mut seed = vec![0u8; 3 * n];
    getrandom::fill(&mut seed).map_err(|e| PqcError::KeyGen(format!("{:?}", e)))?;
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

use falcon::safe_api::{DomainSeparation, FnDsaKeyPair, FnDsaSignature};

fn falcon_keygen(logn: u32, alg: SignAlgorithm) -> Result<SignKeypair, PqcError> {
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

fn falcon_sign(sk: &SigningKey, msg: &[u8]) -> Result<Signature, PqcError> {
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

fn falcon_verify(vk: &VerificationKey, msg: &[u8], sig: &Signature) -> Result<bool, PqcError> {
    match FnDsaSignature::verify(&sig.bytes, &vk.bytes, msg, &DomainSeparation::None) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
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
    #[test]
    fn test_falcon512() {
        let kp = keypair(SignAlgorithm::Falcon512).unwrap();
        let sig = sign(&kp.sk, b"Falcon-512").unwrap();
        assert!(verify(&kp.vk, b"Falcon-512", &sig).unwrap());
    }
    #[test]
    fn test_falcon1024() {
        let kp = keypair(SignAlgorithm::Falcon1024).unwrap();
        let sig = sign(&kp.sk, b"Falcon-1024").unwrap();
        assert!(verify(&kp.vk, b"Falcon-1024", &sig).unwrap());
    }
    #[test]
    fn test_falcon_tampered() {
        let kp = keypair(SignAlgorithm::Falcon512).unwrap();
        let sig = sign(&kp.sk, b"original").unwrap();
        assert!(!verify(&kp.vk, b"tampered", &sig).unwrap());
    }
}
