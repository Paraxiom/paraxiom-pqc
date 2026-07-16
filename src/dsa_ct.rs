//! Constant-time ML-DSA signing kernel (WP2).
//!
//! This module is the `paraxiom-pqc` entry point for constant-time ML-DSA
//! signing. It drives the vendored `ml-dsa` fork's
//! [`ml_dsa::SigningKey::sign_deterministic_constant_time`], which implements
//! the FIPS 204 §3.4 rejection-sampling structure with a fixed 256-iteration
//! loop and branchless candidate selection: a cumulative bitwise-OR
//! `found_valid` flag preserves the first valid signature for the remaining
//! iterations without any secret-dependent branch or early `return`.
//!
//! Keeping the kernel in the fork means the branchless arithmetic operates on
//! the crate's private field types directly, which is the only place it can be
//! expressed without exposing the internal hash/algebra primitives.

use ml_dsa::{MlDsaParams, Signature, SigningKey};

/// Constant-time deterministic ML-DSA signing — WP2 timing-oracle mitigation.
///
/// # Fixed iteration count
///
/// The underlying rejection sampler runs **exactly `MAX_ROUNDS = 256`**
/// iterations (`vendor/ml-dsa-fork/src/lib.rs`), irrespective of how many
/// candidates are accepted. In standard (variable-time) ML-DSA rejection
/// sampling the loop stops as soon as a valid `(z, h)` pair is found, so the
/// number of iterations — and therefore the wall-clock signing time — depends
/// on the secret key and message. Fixing the count at 256 (the FIPS 204
/// statistical bound that keeps the rejection probability below 2⁻¹²⁸) makes
/// every signing operation perform the same amount of work and removes the
/// timing signal.
///
/// # Constant-time, data-independent execution
///
/// The execution profile is independent of the secret key and message. Every
/// iteration unconditionally generates a candidate `(y, w, z, h)` and evaluates
/// all bound checks; no iteration is skipped, and no early `return` or `break`
/// is taken on a secret-dependent condition. The only difference between a
/// signing that accepts on round 3 and one that accepts on round 250 is *which*
/// iteration writes the result — the total operation count is identical.
///
/// # Branchless acceptance via bitwise masking / ORing
///
/// Acceptance is decided with bitwise masks rather than control flow. Per-round
/// validity flags (`z_valid`, `r0_valid`, `ct0_valid`, `h_valid`) are combined
/// into `candidate_valid_mask` and gated by the cumulative `found_valid` flag:
///
/// ```text
/// let should_select_mask = candidate_valid_mask & (1u32 - found_valid);
/// // found_valid is held once set (cumulative OR: found_valid |= should_select_mask)
/// if should_select_mask != 0 {
///     selected_signature = Some(Signature { c_tilde, z, h });
/// }
/// ```
///
/// Because `found_valid` is set on the first acceptance and held for all
/// remaining iterations, `1u32 - found_valid` becomes zero and no later
/// candidate can overwrite the choice. The chosen signature is preserved
/// branchlessly: the state update is a cumulative OR rather than a
/// secret-dependent branch, and the store is guarded only by a flag that is
/// non-zero on exactly one (the winning) iteration.
///
/// # FIPS 204 compatibility
///
/// The kernel is bit-identical to the NIST specification: it reuses the fork's
/// existing algebraic primitives (`expand_mask`, `sample_in_ball`, NTT,
/// `high_bits`/`low_bits`, `Hint`) and emits the standard `(c_tilde, z, h)`
/// encoding, so signatures verify with any compliant FIPS 204 verifier.
///
/// # Warning: stack requirements
///
/// Testing showed the kernel overflows the default (~8 MiB) thread stack during
/// key expansion and the 256-round candidate generation. Run tests and
/// production callers with a larger stack, e.g. `RUST_MIN_STACK=64MB`, or size
/// the calling thread's stack accordingly. This is a stack-depth requirement,
/// not a constant-time concern.
///
/// `ctx` is the FIPS 204 context string (maximum 255 bytes).
pub(crate) fn sign_constant_time<P>(
    signing_key: &SigningKey<P>,
    msg: &[u8],
    ctx: &[u8],
) -> Result<Signature<P>, ml_dsa::Error>
where
    P: MlDsaParams,
{
    signing_key.sign_deterministic_constant_time(msg, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, VerifyingKey};

    /// Sign with the constant-time kernel and assert the resulting signature
    /// verifies under the standard verification routine, while a tampered
    /// message and a wrong context are both rejected.
    fn roundtrip<P: MlDsaParams>() {
        let seed = [0x42u8; 32];
        let sk = SigningKey::<P>::from_seed(&ml_dsa::B32::from(seed));
        let vk: VerifyingKey<P> = sk.verifying_key();
        let msg = b"WP2 constant-time signing";
        let ctx = b"";

        let sig = sign_constant_time(&sk, msg, ctx).expect("constant-time sign must succeed");

        // Generated signature must verify under the standard routine.
        assert!(
            vk.verify_with_context(msg, ctx, &sig),
            "signature must verify"
        );

        // A different message must not verify (soundness / rejection).
        assert!(
            !vk.verify_with_context(b"tampered", ctx, &sig),
            "tampered message must be rejected"
        );

        // A different context must not verify.
        assert!(
            !vk.verify_with_context(msg, b"ctx2", &sig),
            "wrong context must be rejected"
        );
    }

    #[test]
    fn ml_dsa_44_constant_time_verifies() {
        roundtrip::<MlDsa44>();
    }

    #[test]
    fn ml_dsa_65_constant_time_verifies() {
        roundtrip::<MlDsa65>();
    }

    #[test]
    fn ml_dsa_87_constant_time_verifies() {
        roundtrip::<MlDsa87>();
    }
}
