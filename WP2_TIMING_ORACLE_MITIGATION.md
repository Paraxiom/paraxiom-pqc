# WP2: fixed-round ML-DSA signing kernel

Status as of 2026-10-14. This file replaces an earlier description that claimed more than the
code does. The corrections are listed at the end.

## What it is

`SigningKey::sign_deterministic_constant_time` in `vendor/ml-dsa-fork/src/lib.rs` (core loop:
`raw_sign_mu_constant_time`), called through `sign_constant_time` in `src/dsa_ct.rs`.

ML-DSA signing (FIPS 204, Algorithm 7) repeats a loop until a candidate passes four checks:

- `‖z‖∞ < γ₁ − β`
- `‖r₀‖∞ < γ₂ − β`
- `‖c·t₀‖∞ < γ₂`
- the hint `h` has at most ω ones

Upstream ml-dsa stops at the first candidate that passes, so the number of rounds, and with it
the signing time, depends on the key and the message. With deterministic signing a given key and
message always take the same number of rounds, which makes the signing time a stable property of
the key.

The kernel always runs 814 rounds, the lowest loop limit FIPS 204 allows (Appendix C, Table 3),
and keeps the first candidate that passes. Until 2026-10-14 it ran 256. It uses the same
`rho''`, the same `kappa` sequence and the same checks as deterministic ML-DSA.Sign, so it returns
the same signature; `kernel_matches_deterministic_sign` in `src/dsa_ct.rs` compares the two for
all three parameter sets. Signatures verify with any FIPS 204 verifier.

## Where it runs

Only in `sign::sign_deterministic_dangerous`. Since 2026-08-19, `sign::sign` (and
`sign_randomized`) sign ML-DSA in hedged mode through upstream's variable-length loop.

## What is not established

- **Timing.** The kernel has never been timing-measured. The figures in
  `docs/SIDE-CHANNEL-AUDIT.md` were committed on 2026-07-10, two days before the kernel
  (2026-07-12), and describe upstream's loops. Their per-key signing times (319 µs to 1,536 µs)
  are also far below what the kernel costs: it runs 814 rounds where upstream runs 3.85 to 5.1
  on average, 160 to 211 times as many (50 to 66 times at the earlier 256).
  `examples/dudect_timing.rs` measures the kernel since 2026-10-14; no result has been recorded
  yet.
- **Constant time.** The kernel removes the round count from the running time but is not a
  complete constant-time implementation. The round that accepts takes a branch that the others
  skip: `if should_select_mask != 0 { ... }` reduces `z` and stores the signature. The validity
  flags come from ordinary comparisons and `&&`, which the compiler may or may not turn into
  branch-free code, and nothing checks the machine code.

## Loop limit and failure probability

FIPS 204 Appendix C (Table 3) says that an implementation that bounds this loop shall not use a
limit below 814 iterations, which keeps the failure probability at about 2^-256 or less. The
kernel ran 256 rounds until 2026-10-14, below that minimum; it now runs 814.

If one round accepts with probability 1/E, where E is the expected number of rounds, all n
rounds reject with probability (1 − 1/E)^n. FIPS 204 Table 1 gives E for each parameter set:

| Parameter set | E    | n = 814 (now)  | n = 256 (before) |
|---------------|------|----------------|------------------|
| ML-DSA-44     | 4.25 | about 2^-315.0 | about 2^-99.1    |
| ML-DSA-65     | 5.1  | about 2^-256.3 | about 2^-80.6    |
| ML-DSA-87     | 3.85 | about 2^-353.2 | about 2^-111.1   |

When that happens the kernel returns an error; it does not panic.

## Corrections to the earlier version of this file

- 256 is not "the statistical bound used throughout the FIPS 204 reference implementation". The
  only bound in FIPS 204 is a minimum of 814 iterations, which the kernel now uses.
- At 256 rounds the failure probability was about 2^-81 to 2^-111, not "below 2^-128".
- Acceptance is not branchless, and "signing time is now constant" was never measured.
- The third check is `‖c·t₀‖∞ < γ₂`, not `< q − 1`.
- The stack warning (overflow at 8 MiB, `RUST_MIN_STACK=64MB`) does not hold for the current
  code: the kernel tests pass on the default 2 MiB test-thread stack in debug builds.
