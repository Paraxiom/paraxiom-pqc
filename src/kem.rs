//! Key Encapsulation Mechanisms — ML-KEM (FIPS 203)
//!
//! Pure Rust. Zero C.

use crate::PqcError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// KEM security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

/// Encapsulation key (public)
#[derive(Clone)]
pub struct EncapsulationKey {
    pub algorithm: KemAlgorithm,
    pub bytes: Vec<u8>,
}

/// Decapsulation key (secret — stored as 32-byte seed)
///
/// `bytes` is cleared when the key is dropped. Because of that `Drop` impl, `bytes` cannot be
/// moved out of the key; borrow it, clone it, or take it with `std::mem::take(&mut dk.bytes)`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecapsulationKey {
    #[zeroize(skip)]
    pub algorithm: KemAlgorithm,
    pub bytes: Vec<u8>,
}

/// Ciphertext produced by encapsulation
pub struct Ciphertext {
    pub algorithm: KemAlgorithm,
    pub bytes: Vec<u8>,
}

/// Shared secret
///
/// `bytes` is cleared when the secret is dropped; see [`DecapsulationKey`] for what that means
/// for moving `bytes` out.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    pub bytes: Vec<u8>,
}

/// KEM keypair
pub struct KemKeypair {
    pub ek: EncapsulationKey,
    pub dk: DecapsulationKey,
}

/// Generate a KEM keypair
pub fn keypair(algorithm: KemAlgorithm) -> Result<KemKeypair, PqcError> {
    use ml_kem::{Kem, KeyExport, MlKem1024, MlKem512, MlKem768};

    // The backend key (`dk`) clears itself on drop; `seed` is a plain copy and is cleared by
    // `keypair_from_seed`.
    match algorithm {
        KemAlgorithm::MlKem512 => {
            let (dk, _ek) = MlKem512::generate_keypair();
            let mut seed = dk
                .to_seed()
                .ok_or_else(|| PqcError::KeyGen("no seed".into()))?;
            let ek = dk.encapsulation_key().to_bytes().to_vec();
            Ok(keypair_from_seed(algorithm, &mut seed, ek))
        }
        KemAlgorithm::MlKem768 => {
            let (dk, _ek) = MlKem768::generate_keypair();
            let mut seed = dk
                .to_seed()
                .ok_or_else(|| PqcError::KeyGen("no seed".into()))?;
            let ek = dk.encapsulation_key().to_bytes().to_vec();
            Ok(keypair_from_seed(algorithm, &mut seed, ek))
        }
        KemAlgorithm::MlKem1024 => {
            let (dk, _ek) = MlKem1024::generate_keypair();
            let mut seed = dk
                .to_seed()
                .ok_or_else(|| PqcError::KeyGen("no seed".into()))?;
            let ek = dk.encapsulation_key().to_bytes().to_vec();
            Ok(keypair_from_seed(algorithm, &mut seed, ek))
        }
    }
}

/// Builds the key pair from the backend's seed and clears the caller's copy of the seed.
fn keypair_from_seed(algorithm: KemAlgorithm, seed: &mut ml_kem::Seed, ek: Vec<u8>) -> KemKeypair {
    let dk = DecapsulationKey {
        algorithm,
        bytes: seed.to_vec(),
    };
    seed.zeroize();
    KemKeypair {
        ek: EncapsulationKey {
            algorithm,
            bytes: ek,
        },
        dk,
    }
}

/// Copies the backend's shared key into a [`SharedSecret`] and clears the backend copy.
fn shared_secret(ss: &mut ml_kem::SharedKey) -> SharedSecret {
    let out = SharedSecret { bytes: ss.to_vec() };
    ss.zeroize();
    out
}

/// Encapsulate
pub fn encapsulate(ek: &EncapsulationKey) -> Result<(Ciphertext, SharedSecret), PqcError> {
    use ml_kem::{Encapsulate, MlKem1024, MlKem512, MlKem768, TryKeyInit};

    let (ct, mut ss) = match ek.algorithm {
        KemAlgorithm::MlKem512 => {
            let ek_t = ml_kem::EncapsulationKey::<MlKem512>::new_from_slice(&ek.bytes)
                .map_err(|_| PqcError::Encapsulate("invalid key".into()))?;
            let (ct, ss) = ek_t.encapsulate();
            (ct.as_slice().to_vec(), ss)
        }
        KemAlgorithm::MlKem768 => {
            let ek_t = ml_kem::EncapsulationKey::<MlKem768>::new_from_slice(&ek.bytes)
                .map_err(|_| PqcError::Encapsulate("invalid key".into()))?;
            let (ct, ss) = ek_t.encapsulate();
            (ct.as_slice().to_vec(), ss)
        }
        KemAlgorithm::MlKem1024 => {
            let ek_t = ml_kem::EncapsulationKey::<MlKem1024>::new_from_slice(&ek.bytes)
                .map_err(|_| PqcError::Encapsulate("invalid key".into()))?;
            let (ct, ss) = ek_t.encapsulate();
            (ct.as_slice().to_vec(), ss)
        }
    };
    Ok((
        Ciphertext {
            algorithm: ek.algorithm,
            bytes: ct,
        },
        shared_secret(&mut ss),
    ))
}

/// Decapsulate
pub fn decapsulate(dk: &DecapsulationKey, ct: &Ciphertext) -> Result<SharedSecret, PqcError> {
    use ml_kem::{Decapsulate, KeyInit, MlKem1024, MlKem512, MlKem768, Seed};

    // Borrowed from `dk.bytes`, so no copy of the seed is made here. The backend keys built
    // from it (`dk_t`) clear themselves on drop.
    let seed: &Seed = dk
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| PqcError::Decapsulate("invalid seed size (expected 32 bytes)".into()))?;

    let mut ss: ml_kem::SharedKey = match dk.algorithm {
        KemAlgorithm::MlKem512 => {
            let dk_t = ml_kem::DecapsulationKey::<MlKem512>::new(seed);
            let ct_t = ml_kem::Ciphertext::<MlKem512>::try_from(ct.bytes.as_slice())
                .map_err(|_| PqcError::Decapsulate("invalid ciphertext".into()))?;
            dk_t.decapsulate(&ct_t)
        }
        KemAlgorithm::MlKem768 => {
            let dk_t = ml_kem::DecapsulationKey::<MlKem768>::new(seed);
            let ct_t = ml_kem::Ciphertext::<MlKem768>::try_from(ct.bytes.as_slice())
                .map_err(|_| PqcError::Decapsulate("invalid ciphertext".into()))?;
            dk_t.decapsulate(&ct_t)
        }
        KemAlgorithm::MlKem1024 => {
            let dk_t = ml_kem::DecapsulationKey::<MlKem1024>::new(seed);
            let ct_t = ml_kem::Ciphertext::<MlKem1024>::try_from(ct.bytes.as_slice())
                .map_err(|_| PqcError::Decapsulate("invalid ciphertext".into()))?;
            dk_t.decapsulate(&ct_t)
        }
    };
    Ok(shared_secret(&mut ss))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_512_roundtrip() {
        let kp = keypair(KemAlgorithm::MlKem512).unwrap();
        let (ct, ss_enc) = encapsulate(&kp.ek).unwrap();
        let ss_dec = decapsulate(&kp.dk, &ct).unwrap();
        assert_eq!(ss_enc.bytes, ss_dec.bytes);
    }

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let kp = keypair(KemAlgorithm::MlKem768).unwrap();
        let (ct, ss_enc) = encapsulate(&kp.ek).unwrap();
        let ss_dec = decapsulate(&kp.dk, &ct).unwrap();
        assert_eq!(ss_enc.bytes, ss_dec.bytes);
    }

    #[test]
    fn test_ml_kem_1024_roundtrip() {
        let kp = keypair(KemAlgorithm::MlKem1024).unwrap();
        let (ct, ss_enc) = encapsulate(&kp.ek).unwrap();
        let ss_dec = decapsulate(&kp.dk, &ct).unwrap();
        assert_eq!(ss_enc.bytes, ss_dec.bytes);
    }

    fn zeroize_on_drop<T: ZeroizeOnDrop>() {}

    /// Compile-time check: the secret types, and the backend key that `decapsulate` builds,
    /// clear themselves on drop. Fails to build if the `zeroize` derive or the ml-kem
    /// `zeroize` feature is removed. tests/zeroize.rs checks the heap buffers themselves.
    #[test]
    fn secret_types_zeroize_on_drop() {
        zeroize_on_drop::<DecapsulationKey>();
        zeroize_on_drop::<SharedSecret>();
        zeroize_on_drop::<ml_kem::DecapsulationKey<ml_kem::MlKem512>>();
        zeroize_on_drop::<ml_kem::DecapsulationKey<ml_kem::MlKem768>>();
        zeroize_on_drop::<ml_kem::DecapsulationKey<ml_kem::MlKem1024>>();
    }

    #[test]
    fn zeroize_clears_secret_bytes() {
        let mut kp = keypair(KemAlgorithm::MlKem768).unwrap();
        let (_ct, mut ss) = encapsulate(&kp.ek).unwrap();
        assert!(!kp.dk.bytes.is_empty() && !ss.bytes.is_empty());
        kp.dk.zeroize();
        ss.zeroize();
        assert!(kp.dk.bytes.is_empty());
        assert!(ss.bytes.is_empty());
        assert_eq!(kp.dk.algorithm, KemAlgorithm::MlKem768);
    }
}
