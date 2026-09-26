//! Falcon verification without the rest of `sign`.
//!
//! Consumers that only check Falcon signatures (a node verifying an RPC
//! caller) enable `falcon-verify` and get this module alone, without the
//! ml-dsa / slh-dsa dependencies `sign` brings in. `sign::verify` uses the
//! same function, so both paths accept exactly the same signatures.

use falcon::safe_api::{DomainSeparation, FnDsaSignature};

/// Verify a Falcon-512 or Falcon-1024 signature. The degree comes from the
/// key's header byte. Encodings are those produced by `sign::sign` (and by
/// falcon-rs `FnDsaKeyPair`): raw public key bytes, `FnDsaSignature` bytes,
/// no domain separation.
pub fn verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    FnDsaSignature::verify(sig, vk, msg, &DomainSeparation::None).is_ok()
}
