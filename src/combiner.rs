//! Crypto-agile key combiner (ADR 0001, plan step 1).
//!
//! Combines an ordered set of shared secrets (a QKD key, ML-KEM shared secrets, a
//! pre-shared key) into one 32-byte key bound to a context such as a handshake
//! transcript. The mechanism set is chosen per link with a [`Policy`]: inputs that do
//! not match the policy are rejected, so a missing input cannot silently downgrade the
//! link (fail closed).
//!
//! # Construction
//!
//! SHA3-256 over an injective, length-prefixed encoding:
//!
//! ```text
//! "paraxiom-pqc/combiner/v1" || count:u8
//!     || for each input: mechanism-id:u8 || len:u32be || secret
//!     || len:u32be || context
//! ```
//!
//! # Security
//!
//! The output is unpredictable as long as at least ONE input is unpredictable to the
//! adversary: if an input has min-entropy `k` given everything else the adversary knows,
//! an adversary making `q` hash queries distinguishes the output from random with
//! advantage at most `q / 2^k` (SHA3-256 modelled as a random oracle). The encoding is
//! injective, so two different input lists never produce the same hash input; this is
//! machine-checked in `lean/Combiner.lean` (`encode_injective`). The combined key is
//! never stronger than its strongest input.
//!
//! [`qkd_pqc_v2`] reproduces PQTG's existing QKD + PQC mixing (`mix_keys`) byte for byte,
//! so PQTG can adopt this module without changing anything on the wire.

use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// Domain-separation label of the v1 encoding.
pub const COMBINER_LABEL: &[u8] = b"paraxiom-pqc/combiner/v1";

/// Label of PQTG's QKD + PQC mixing, kept for wire compatibility.
pub const PQTG_MIXING_LABEL: &[u8] = b"pqtg-key-mixing-v2";

/// Shortest secret accepted for QKD and pre-shared inputs (128 bits).
pub const MIN_SECRET_LEN: usize = 16;

/// The mechanism that produced a secret. The identifier is bound into the hash, so the
/// same bytes labelled with a different mechanism give a different key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mechanism {
    /// A key delivered by a QKD system (for example over ETSI GS QKD 014).
    Qkd,
    /// ML-KEM-512 shared secret (FIPS 203).
    MlKem512,
    /// ML-KEM-768 shared secret (FIPS 203).
    MlKem768,
    /// ML-KEM-1024 shared secret (FIPS 203).
    MlKem1024,
    /// A pre-shared symmetric key.
    PreShared,
}

impl Mechanism {
    /// One-byte identifier used in the encoding. Never reuse a retired value.
    pub const fn id(self) -> u8 {
        match self {
            Mechanism::Qkd => 0x01,
            Mechanism::MlKem512 => 0x10,
            Mechanism::MlKem768 => 0x11,
            Mechanism::MlKem1024 => 0x12,
            Mechanism::PreShared => 0x20,
        }
    }

    fn accepts_len(self, len: usize) -> bool {
        match self {
            Mechanism::MlKem512 | Mechanism::MlKem768 | Mechanism::MlKem1024 => len == 32,
            Mechanism::Qkd | Mechanism::PreShared => len >= MIN_SECRET_LEN && len <= u32::MAX as usize,
        }
    }
}

/// One input secret and the mechanism that produced it.
#[derive(Clone, Copy, Debug)]
pub struct Secret<'a> {
    pub mechanism: Mechanism,
    pub bytes: &'a [u8],
}

impl<'a> Secret<'a> {
    pub fn new(mechanism: Mechanism, bytes: &'a [u8]) -> Self {
        Self { mechanism, bytes }
    }
}

/// Why a combination was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CombinerError {
    #[error("a policy needs between 1 and 255 mechanisms")]
    PolicySize,
    #[error("mechanism {0:?} appears twice in the policy")]
    DuplicateMechanism(Mechanism),
    #[error("policy expects {expected} secrets, got {got}")]
    WrongCount { expected: usize, got: usize },
    #[error("secret {index}: policy expects {expected:?}, got {got:?}")]
    WrongMechanism { index: usize, expected: Mechanism, got: Mechanism },
    #[error("secret {index} ({mechanism:?}) has an invalid length {len}")]
    BadLength { index: usize, mechanism: Mechanism, len: usize },
    #[error("context longer than 2^32 - 1 bytes")]
    ContextTooLong,
}

/// The ordered set of mechanisms a link requires, chosen by configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    mechanisms: Vec<Mechanism>,
}

impl Policy {
    /// A policy requiring exactly these mechanisms, in this order.
    pub fn new(mechanisms: &[Mechanism]) -> Result<Self, CombinerError> {
        if mechanisms.is_empty() || mechanisms.len() > 255 {
            return Err(CombinerError::PolicySize);
        }
        for (i, m) in mechanisms.iter().enumerate() {
            if mechanisms[..i].contains(m) {
                return Err(CombinerError::DuplicateMechanism(*m));
            }
        }
        Ok(Self { mechanisms: mechanisms.to_vec() })
    }

    pub fn mechanisms(&self) -> &[Mechanism] {
        &self.mechanisms
    }

    /// Combine `secrets` under this policy, bound to `context`.
    ///
    /// Fails closed: the secrets must match the policy's mechanisms one for one, in order.
    pub fn combine(&self, secrets: &[Secret<'_>], context: &[u8]) -> Result<Zeroizing<[u8; 32]>, CombinerError> {
        if secrets.len() != self.mechanisms.len() {
            return Err(CombinerError::WrongCount { expected: self.mechanisms.len(), got: secrets.len() });
        }
        for (index, (s, m)) in secrets.iter().zip(&self.mechanisms).enumerate() {
            if s.mechanism != *m {
                return Err(CombinerError::WrongMechanism { index, expected: *m, got: s.mechanism });
            }
            if !s.mechanism.accepts_len(s.bytes.len()) {
                return Err(CombinerError::BadLength { index, mechanism: s.mechanism, len: s.bytes.len() });
            }
        }
        if context.len() > u32::MAX as usize {
            return Err(CombinerError::ContextTooLong);
        }

        let mut h = Sha3_256::new();
        h.update(COMBINER_LABEL);
        h.update([secrets.len() as u8]);
        for s in secrets {
            h.update([s.mechanism.id()]);
            h.update((s.bytes.len() as u32).to_be_bytes());
            h.update(s.bytes);
        }
        h.update((context.len() as u32).to_be_bytes());
        h.update(context);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&h.finalize());
        Ok(out)
    }
}

/// PQTG's QKD + PQC mixing, unchanged ("pqtg-key-mixing-v2"):
/// `SHA3-256(label || len(qkd):u32be || qkd || pqc)`.
///
/// Kept so PQTG can move to this crate without a wire change; new designs should use
/// [`Policy::combine`], which also binds the mechanisms and a context.
pub fn qkd_pqc_v2(qkd_key: &[u8], pqc_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(PQTG_MIXING_LABEL);
    h.update((qkd_key.len() as u32).to_be_bytes());
    h.update(qkd_key);
    h.update(pqc_key);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&h.finalize());
    out
}
