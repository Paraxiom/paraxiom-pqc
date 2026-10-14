//! Fixed-round ML-DSA signing kernel (WP2), used only by
//! [`crate::sign::sign_deterministic_dangerous`].
//!
//! [`sign_constant_time`] drives the vendored fork's
//! [`ml_dsa::SigningKey::sign_deterministic_constant_time`]. It runs the FIPS 204 signing loop for
//! a fixed 256 rounds and keeps the first candidate that passes the four bound checks, so the
//! number of rounds no longer shows in the running time. The result is the deterministic FIPS 204
//! signature (the tests below compare it with the fork's variable-length `sign_deterministic`).
//! The kernel lives in the fork because it works on the crate's private field types.
//!
//! What the kernel is not, as of 2026-10-14:
//!
//! - **Not the default.** [`crate::sign::sign`] signs ML-DSA in hedged mode through upstream's
//!   variable-length loop. This kernel runs only in `sign_deterministic_dangerous`.
//! - **Not fully constant time.** The round that accepts takes a branch that the other rounds skip
//!   (it reduces `z` and stores the signature; `raw_sign_mu_constant_time` in
//!   `vendor/ml-dsa-fork/src/lib.rs`), and the bound checks are ordinary comparisons whose machine
//!   code is up to the compiler.
//! - **Not measured.** No timing measurement of this kernel exists. The figures in
//!   `docs/SIDE-CHANNEL-AUDIT.md` were committed on 2026-07-10, two days before the kernel, and
//!   describe upstream's loops.
//! - **Not within the FIPS 204 loop limit.** FIPS 204 Appendix C (Table 3) sets 814 iterations as
//!   the lowest limit an implementation may put on this loop. When all 256 rounds reject, the
//!   kernel returns an error. With E the expected number of rounds from FIPS 204 Table 1, that
//!   happens with probability (1 - 1/E)^256:
//!
//!   | Parameter set | E    | (1 - 1/E)^256   |
//!   |---------------|------|-----------------|
//!   | ML-DSA-44     | 4.25 | about 2^-99.1   |
//!   | ML-DSA-65     | 5.1  | about 2^-80.6   |
//!   | ML-DSA-87     | 3.85 | about 2^-111.1  |
//!
//!   An earlier version of this comment called 256 "the FIPS 204 statistical bound" and put the
//!   failure probability below 2^-128. Both were wrong.
//! - **Slower.** Every signature costs 256 rounds, against 3.85 to 5.1 on average for
//!   [`crate::sign::sign`]. In a release build on one machine it was roughly 25 to 50 times slower.

use ml_dsa::{MlDsaParams, Signature, SigningKey};

/// Deterministic ML-DSA signing with the fixed-round kernel. See the module notes for what it
/// does and does not guarantee.
///
/// `ctx` is the FIPS 204 context string (at most 255 bytes).
///
/// # Errors
///
/// Fails if `ctx` is longer than 255 bytes or if every round rejects.
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

    /// Sign with the kernel and check that the signature verifies under the standard routine,
    /// while a tampered message and a wrong context are both rejected.
    fn roundtrip<P: MlDsaParams>() {
        let seed = [0x42u8; 32];
        let sk = SigningKey::<P>::from_seed(&ml_dsa::B32::from(seed));
        let vk: VerifyingKey<P> = sk.verifying_key();
        let msg = b"WP2 constant-time signing";
        let ctx = b"";

        let sig = sign_constant_time(&sk, msg, ctx).expect("kernel signing must succeed");

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

    /// The kernel returns exactly the signature of deterministic ML-DSA.Sign, computed by the
    /// fork's variable-length `sign_deterministic`: same rho'', same kappa sequence, same checks.
    fn matches_deterministic_sign<P: MlDsaParams>() {
        for i in 0u8..2 {
            let sk = SigningKey::<P>::from_seed(&ml_dsa::B32::from([i ^ 0x3c; 32]));
            let msg = [i; 48];
            let kernel = sign_constant_time(&sk, &msg, b"ctx").unwrap();
            let reference = sk.sign_deterministic(&msg, b"ctx").unwrap();
            assert_eq!(kernel.encode(), reference.encode());
        }
    }

    #[test]
    fn kernel_matches_deterministic_sign() {
        matches_deterministic_sign::<MlDsa44>();
        matches_deterministic_sign::<MlDsa65>();
        matches_deterministic_sign::<MlDsa87>();
    }

    #[test]
    fn kernel_refuses_a_long_context() {
        let sk = SigningKey::<MlDsa44>::from_seed(&ml_dsa::B32::from([1u8; 32]));
        assert!(sign_constant_time(&sk, b"msg", &[0u8; 256]).is_err());
    }
}
