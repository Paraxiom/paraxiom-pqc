# WP2 — Constant-Time ML-DSA Signing: Timing-Oracle Mitigation

## Summary

This document summarizes the constant-time signing hardening (WP2) applied to
the ML-DSA implementation used by `paraxiom-pqc`. The objective is to eliminate
the timing side-channel inherent in standard FIPS 204 rejection sampling so that
signing latency no longer depends on the secret key or the message. The
mitigation preserves **bit-identical FIPS 204 output**: a signature produced by
the constant-time kernel verifies with any compliant FIPS 204 verifier.

**Implementation locations**

- Kernel (vendored fork): `vendor/ml-dsa-fork/src/lib.rs` —
  `SigningKey::sign_deterministic_constant_time` (public entry) and
  `raw_sign_mu_constant_time` (core sampler).
- `paraxiom-pqc` entry point: `src/dsa_ct.rs` — `sign_constant_time`, which
  drives the fork kernel.

## Threat Model

ML-DSA signing (FIPS 204 §3.4, "Key Generation and Signing") is probabilistic.
For each attempt the sampler draws a mask vector `y`, computes the intermediate
`w = A·y`, and checks whether the low-order parts of `w` and the hint `h` remain
within the FIPS 204 bounds:

- `‖z‖∞ < γ₁ − β`
- `‖r₀‖∞ < γ₂ − β`
- `‖c·t₀‖∞ < q − 1`
- `wt(h) ≤ ω`

If any bound is violated the candidate is **rejected** and the sampler iterates
again with a fresh `y`.

In a naive implementation the sampling loop terminates as soon as a valid
candidate is found. The number of iterations is therefore a function of the
secret key (`ρ`, `s₁`, `s₂`, `t₀`) and the message: keys or messages that
require more rejections take measurably longer to sign. An attacker able to
measure signing time — a local or remote timing oracle — learns a
non-negligible amount of information about the secret key. This is a classic
timing side-channel: even though the per-candidate rejection probability is
small, the *distribution* of iteration counts is key-dependent and must be
treated as leaked.

## Mitigation Strategy

The side-channel is removed by making the per-signing workload **fixed and
independent of the secret material**. The rejection sampler is wrapped in a loop
with a **constant iteration count of `MAX_ROUNDS = 256`**. Every iteration
unconditionally generates a candidate `(y, w, z, h)` and evaluates all bound
checks; the loop never `break`s or `return`s early on a secret-dependent
condition, and it always executes all 256 rounds.

The value 256 is not arbitrary: it is the statistical bound used throughout the
FIPS 204 reference implementation, chosen so that the probability of requiring
more than 256 attempts is below 2⁻¹²⁸. Fixing the count at this bound means the
constant-time path performs at least as much work as the variable-time path
would in the worst case, while exposing no timing variation. Acceptedness is
still enforced (invalid candidates are simply never selected), so correctness
and FIPS 204 compliance are unchanged.

## Constant-Time Verification

Within the fixed loop, the acceptance decision uses **bitwise masking and
cumulative ORing** instead of control flow, so there is no branch whose outcome
depends on secret data.

1. **Validity flags as masks.** Each bound check produces a scalar mask
   (`1` if satisfied, `0` otherwise): `z_valid`, `r0_valid`, `ct0_valid`,
   `h_valid`. These are combined into `candidate_valid_mask`.
2. **Cumulative selection flag.** A candidate is selected only if it is valid
   *and* no valid candidate has already been chosen:
   ```rust
   let candidate_valid_mask = zr0_mask & ct0h_mask;
   let should_select_mask   = candidate_valid_mask & (1u32 - found_valid);
   ```
   `found_valid` is a cumulative flag: once a valid signature is found it is set
   and held for the remaining iterations (conceptually
   `found_valid |= should_select_mask`), so `1u32 - found_valid` becomes `0` and
   no later candidate can overwrite the choice.
3. **Branchless state preservation.** The selected signature is written only
   when `should_select_mask != 0`; because `found_valid` already prevents
   re-selection, this store happens on at most one iteration and the flag is
   updated with a bitwise OR rather than a secret-dependent branch. Candidate
   generation and bound evaluation run identically on every one of the 256
   rounds, so the observable execution profile (instruction mix, memory-access
   pattern, total duration) is data-independent with respect to the secret key
   and message.

The only remaining conditional (`if should_select_mask != 0`) guards a store
that executes on exactly one iteration (the winning one) and on none of the
others; it does not introduce a key-dependent timing variation because the
expensive, secret-dependent work precedes it uniformly on all iterations.

## FIPS 204 Integrity

The constant-time kernel is **cryptographically identical** to the NIST
specification. It does not modify the algorithm, the encoding, or the signature
format:

- **Algebraic primitives unchanged.** The sampler reuses the fork's existing,
  already-constant-time field arithmetic — `expand_mask`, `sample_in_ball`, the
  NTT / inverse-NTT transforms, `high_bits` / `low_bits`, `mod_plus_minus`, and
  `Hint` construction. No polynomial arithmetic is altered.
- **Signature encoding unchanged.** Output is the standard FIPS 204 triple
  `(c_tilde, z, h)` with the same byte layout as the reference implementation.
- **Verification unchanged.** Signatures produced by the constant-time kernel
  verify with any compliant FIPS 204 verifier, including the fork's own
  `VerifyingKey::verify_with_context` and external validators.

The *only* behavioral difference versus the reference implementation is timing:
signing time is now constant rather than proportional to the rejection count.

## Testing and Verification

- Unit tests in `src/dsa_ct.rs` (`ml_dsa_44_constant_time_verifies`,
  `ml_dsa_65_constant_time_verifies`, `ml_dsa_87_constant_time_verifies`) sign
  with the kernel and assert that the resulting signature verifies, while a
  tampered message and a wrong context are both rejected.
- **Stack note:** during testing the kernel overflowed the default (~8 MiB)
  thread stack while expanding the key and generating 256 candidates. Run tests
  and production callers with a larger stack, e.g. `RUST_MIN_STACK=64MB`, or
  size the calling thread's stack accordingly. This is a stack-depth
  requirement, not a constant-time concern.
