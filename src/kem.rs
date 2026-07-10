//! Key Encapsulation Mechanisms — ML-KEM (FIPS 203)
//!
//! Pure Rust. Zero C.

use crate::PqcError;

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
pub struct DecapsulationKey {
    pub algorithm: KemAlgorithm,
    pub bytes: Vec<u8>,
}

/// Ciphertext produced by encapsulation
pub struct Ciphertext {
    pub algorithm: KemAlgorithm,
    pub bytes: Vec<u8>,
}

/// Shared secret
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

    match algorithm {
        KemAlgorithm::MlKem512 => {
            let (dk, _ek) = MlKem512::generate_keypair();
            let seed = dk
                .to_seed()
                .ok_or_else(|| PqcError::KeyGen("no seed".into()))?;
            let ek_ref = dk.encapsulation_key();
            Ok(KemKeypair {
                ek: EncapsulationKey {
                    algorithm,
                    bytes: ek_ref.to_bytes().to_vec(),
                },
                dk: DecapsulationKey {
                    algorithm,
                    bytes: seed.to_vec(),
                },
            })
        }
        KemAlgorithm::MlKem768 => {
            let (dk, _ek) = MlKem768::generate_keypair();
            let seed = dk
                .to_seed()
                .ok_or_else(|| PqcError::KeyGen("no seed".into()))?;
            let ek_ref = dk.encapsulation_key();
            Ok(KemKeypair {
                ek: EncapsulationKey {
                    algorithm,
                    bytes: ek_ref.to_bytes().to_vec(),
                },
                dk: DecapsulationKey {
                    algorithm,
                    bytes: seed.to_vec(),
                },
            })
        }
        KemAlgorithm::MlKem1024 => {
            let (dk, _ek) = MlKem1024::generate_keypair();
            let seed = dk
                .to_seed()
                .ok_or_else(|| PqcError::KeyGen("no seed".into()))?;
            let ek_ref = dk.encapsulation_key();
            Ok(KemKeypair {
                ek: EncapsulationKey {
                    algorithm,
                    bytes: ek_ref.to_bytes().to_vec(),
                },
                dk: DecapsulationKey {
                    algorithm,
                    bytes: seed.to_vec(),
                },
            })
        }
    }
}

/// Encapsulate
pub fn encapsulate(ek: &EncapsulationKey) -> Result<(Ciphertext, SharedSecret), PqcError> {
    use ml_kem::{Encapsulate, MlKem1024, MlKem512, MlKem768, TryKeyInit};

    match ek.algorithm {
        KemAlgorithm::MlKem512 => {
            let ek_t = ml_kem::EncapsulationKey::<MlKem512>::new_from_slice(&ek.bytes)
                .map_err(|_| PqcError::Encapsulate("invalid key".into()))?;
            let (ct, ss) = ek_t.encapsulate();
            Ok((
                Ciphertext {
                    algorithm: ek.algorithm,
                    bytes: ct.as_slice().to_vec(),
                },
                SharedSecret {
                    bytes: <[u8]>::as_ref(&ss).to_vec(),
                },
            ))
        }
        KemAlgorithm::MlKem768 => {
            let ek_t = ml_kem::EncapsulationKey::<MlKem768>::new_from_slice(&ek.bytes)
                .map_err(|_| PqcError::Encapsulate("invalid key".into()))?;
            let (ct, ss) = ek_t.encapsulate();
            Ok((
                Ciphertext {
                    algorithm: ek.algorithm,
                    bytes: ct.as_slice().to_vec(),
                },
                SharedSecret {
                    bytes: <[u8]>::as_ref(&ss).to_vec(),
                },
            ))
        }
        KemAlgorithm::MlKem1024 => {
            let ek_t = ml_kem::EncapsulationKey::<MlKem1024>::new_from_slice(&ek.bytes)
                .map_err(|_| PqcError::Encapsulate("invalid key".into()))?;
            let (ct, ss) = ek_t.encapsulate();
            Ok((
                Ciphertext {
                    algorithm: ek.algorithm,
                    bytes: ct.as_slice().to_vec(),
                },
                SharedSecret {
                    bytes: <[u8]>::as_ref(&ss).to_vec(),
                },
            ))
        }
    }
}

/// Decapsulate
pub fn decapsulate(dk: &DecapsulationKey, ct: &Ciphertext) -> Result<SharedSecret, PqcError> {
    use ml_kem::{Decapsulate, KeyInit, MlKem1024, MlKem512, MlKem768, Seed};

    let seed: &Seed = dk
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| PqcError::Decapsulate("invalid seed size (expected 32 bytes)".into()))?;

    match dk.algorithm {
        KemAlgorithm::MlKem512 => {
            let dk_t = ml_kem::DecapsulationKey::<MlKem512>::new(seed);
            let ct_t = ml_kem::Ciphertext::<MlKem512>::try_from(ct.bytes.as_slice())
                .map_err(|_| PqcError::Decapsulate("invalid ciphertext".into()))?;
            Ok(SharedSecret {
                bytes: {
                    let sk: ml_kem::SharedKey = dk_t.decapsulate(&ct_t);
                    sk.to_vec()
                },
            })
        }
        KemAlgorithm::MlKem768 => {
            let dk_t = ml_kem::DecapsulationKey::<MlKem768>::new(seed);
            let ct_t = ml_kem::Ciphertext::<MlKem768>::try_from(ct.bytes.as_slice())
                .map_err(|_| PqcError::Decapsulate("invalid ciphertext".into()))?;
            Ok(SharedSecret {
                bytes: {
                    let sk: ml_kem::SharedKey = dk_t.decapsulate(&ct_t);
                    sk.to_vec()
                },
            })
        }
        KemAlgorithm::MlKem1024 => {
            let dk_t = ml_kem::DecapsulationKey::<MlKem1024>::new(seed);
            let ct_t = ml_kem::Ciphertext::<MlKem1024>::try_from(ct.bytes.as_slice())
                .map_err(|_| PqcError::Decapsulate("invalid ciphertext".into()))?;
            Ok(SharedSecret {
                bytes: {
                    let sk: ml_kem::SharedKey = dk_t.decapsulate(&ct_t);
                    sk.to_vec()
                },
            })
        }
    }
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
}
