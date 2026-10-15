//! Falcon verification without the rest of `sign`.
//!
//! Consumers that only check Falcon signatures (a node verifying an RPC
//! caller) enable `falcon-verify` and get this module alone, without the
//! ml-dsa / slh-dsa dependencies `sign` brings in. `sign::verify` uses the
//! same function, so both paths accept exactly the same signatures.
//!
//! Verification uses integer arithmetic only (decoding, hashing to a point,
//! NTT modulo q, a norm check), so it works on every target. Falcon key
//! generation and signing use floating point on secret values and are built
//! only where that runs in hardware; see `sign::FALCON_SIGNING_AVAILABLE`.

use falcon::safe_api::{DomainSeparation, FnDsaSignature};

/// Encoded public key length for Falcon-512 (logn 9) and Falcon-1024 (logn 10).
const PUBLIC_KEY_LEN_512: usize = 897;
const PUBLIC_KEY_LEN_1024: usize = 1793;

/// The degree (log2 n) of a Falcon-512 or Falcon-1024 public key: 9 or 10.
///
/// `None` for anything else, including keys of the other degrees falcon-rs can
/// parse (n = 2 to 256), which offer no meaningful security. The header byte is
/// `0x00 + logn` and the length must be the one for that degree.
pub(crate) fn public_key_logn(vk: &[u8]) -> Option<u32> {
    match (vk.first(), vk.len()) {
        (Some(0x09), PUBLIC_KEY_LEN_512) => Some(9),
        (Some(0x0A), PUBLIC_KEY_LEN_1024) => Some(10),
        _ => None,
    }
}

/// Verify a Falcon-512 or Falcon-1024 signature. The degree comes from the
/// key's header byte, and keys of any other degree or length are refused
/// (`false`). Encodings are those produced by `sign::sign` (and by falcon-rs
/// `FnDsaKeyPair`): raw public key bytes, `FnDsaSignature` bytes, no domain
/// separation.
///
/// Before 0.2.0 this accepted every degree falcon-rs supports, n = 2 to 1024.
pub fn verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    public_key_logn(vk).is_some()
        && FnDsaSignature::verify(sig, vk, msg, &DomainSeparation::None).is_ok()
}
