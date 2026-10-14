# Timing measurements: paraxiom-pqc signing and ML-KEM decapsulation

A first-pass measurement of the **timing** channel of the `paraxiom-pqc` primitives. It is an
internal measurement, not an audit; nothing in this repository has been externally audited.
Power and EM analysis are out of scope here (they need lab instrumentation, the basis for the
planned CSIT Belfast collaboration). This covers what software can measure on the target
silicon.

## Status (2026-10-14): which code these numbers describe

These results were committed on 2026-07-10 and describe the code of that date. Since then:

- From 2026-07-12 the deterministic ML-DSA path runs a fixed-round kernel (`src/dsa_ct.rs`;
  first through `sign`, and since 2026-08-19 through `sign_deterministic_dangerous`). The
  kernel has **never been measured**. The "ML-DSA-44 deterministic" rows below are upstream's
  variable-length loop, not the kernel. See `WP2_TIMING_ORACLE_MITIGATION.md`.
- Since 2026-08-19 `sign` is hedged for ML-DSA. The "randomized (hedged)" rows below describe
  the loop that `sign` runs today.
- Until 2026-10-14 the "deterministic" row of `examples/dudect_timing.rs` called `sign`, so a
  rerun between 2026-08-19 and that date measured hedged signing in both ML-DSA rows. The
  example now times `sign_deterministic_dangerous` (the kernel) and `sign` (hedged).

## Method

`examples/dudect_timing.rs` implements a dudect-style test (Reparaz et al., *"dude, is my code
constant time?"*). For each scheme it interleaves two measurement classes, a **fixed** secret key
and a pool of **random** keys, signs a fixed message, times only the signing call, and runs
**Welch's t-test** on the two timing populations with upper-percentile cropping (the lower
measurements are cleaner). **|t| > 4.5 means statistically significant key-dependent timing**
(about 10^-5 false positives). A |t| below 4.5 means no difference was detected at that sample
size; it does not prove constant time. SLH-DSA (hash-based) is the control that validates the
harness.

Run on two CPUs: an x86-64 host and the deployment target, an Arm **Cortex-A53** (Xilinx Kria
KR260).

## Results

**x86-64**

| Scheme / mode | \|t\| | verdict |
|---------------|------:|---------|
| SLH-DSA-128f (control) | 0.66 | no leak detected |
| Falcon-512 | 3.08 | no leak detected |
| **ML-DSA-44 deterministic (upstream loop)** | **112.8** | **leak** |
| ML-DSA-44 randomized (hedged) | 4.4 | no leak detected |

**aarch64 (Cortex-A53, target silicon)**

| Scheme / mode | \|t\| | verdict |
|---------------|------:|---------|
| SLH-DSA-128f (control) | 4.18 | no leak detected |
| Falcon-512 | 3.34 | no leak detected |
| **ML-DSA-44 deterministic (upstream loop)** | **98.7** | **leak** |
| ML-DSA-44 randomized (hedged) | 1.5 | no leak detected |

The leak, and its disappearance under hedged signing, show on both CPUs.

## Finding: deterministic ML-DSA signing leaks key-dependent timing

ML-DSA signing uses **rejection sampling**: it retries until a candidate passes the norm bounds,
and the retry count depends on the key and the message. With **deterministic** signing (the
default on 2026-07-10, upstream's `sign_deterministic`), a given key and message always take the
same number of retries, so each key has a **stable, reproducible signing time**.

Disambiguation (12 independent keys, deterministic, 3000 signatures each): the per-key mean
signing time spread **4.8 times** (319 µs to 1,536 µs). The dudect signal is real key-dependent
timing, not an artifact of one unlucky fixed key.

Whether timing *alone* allows key recovery is a deeper question (the kind a power/EM lab
answers), but a stable per-key timing fingerprint is a measurable leak that should be removed.

## Mitigation: hedged (randomized) signing

FIPS 204 §3.4 allows **hedged** signing, with fresh randomness for each signature. Since
2026-08-19 `paraxiom_pqc::sign::sign` signs ML-DSA this way (through ml-dsa's `sign_randomized`,
behind its `rand_core` feature); `sign_randomized` is the same path. Falcon is randomized by
construction and SLH-DSA delegates to `sign`.

Effect: the retry count is random for each signature, so a fixed key's signing time **varies**
instead of being a fingerprint. Measured: the dudect statistic drops from **|t| 112.8 to 4.4** on
x86-64, below the detection threshold.

## ML-KEM-768 decapsulation (valid against invalid ciphertext)

ML-KEM's Fujisaki-Okamoto transform *implicitly rejects* an invalid ciphertext: it returns a
pseudorandom shared secret instead of an error. Decapsulation must take the **same time** for a
valid and a tampered ciphertext; otherwise its timing is a **validity oracle** (a known
Kyber/ML-KEM side-channel class). `examples/dudect_kem.rs` runs the dudect test over interleaved
valid and invalid (one flipped byte) ciphertexts:

| Ciphertext | decapsulation time (x86-64) |
|------------|-----------------------------|
| valid | about 137.0 µs |
| invalid (tampered) | about 137.0 µs |
| **dudect statistic** | **\|t\| = 1.3** |

**Result: no validity timing difference detected** (|t| 1.3, well below 4.5) on x86-64. The
aarch64 measurement is still to do.

- ML-KEM decapsulation timing: `measured (evidence: sidechannel-mlkem-decap-x86.txt)`

## Limits

- **Timing channel only.** Power and EM side channels are not covered and may leak where timing
  does not; that is the purpose of the CSIT lab work.
- **Hedging removes the per-key fingerprint, not the data dependence.** The *expected* retry
  count still depends on the key; |t| 4.4 is just below the threshold at about 10^4 samples and
  may rise with more samples.
- **The fixed-round kernel is unmeasured** (see the status note above).
- **Falcon showed no mean-timing difference** here, but its floating-point Gaussian sampler
  remains the classic power/EM concern; no timing signal does not mean no side channel. Falcon
  signing is built only on x86/x86_64 with SSE2 and AArch64 with NEON
  (`sign::FALCON_SIGNING_AVAILABLE`).
- The backend crates (`ml-kem`, `ml-dsa`, `slh-dsa`, RustCrypto) are pre-release (rc.*).

## Summary

| Primitive | timing result | notes |
|-----------|---------------|-------|
| SLH-DSA-SHAKE-128f | no leak detected | hash-based; control |
| Falcon-512 | no leak detected | floating-point sampler; power/EM not tested |
| ML-DSA, deterministic, upstream loop | **leaks** | rejection sampling; measured before 2026-07-12 |
| ML-DSA, deterministic, fixed-round kernel | **not measured** | `sign_deterministic_dangerous` |
| ML-DSA, hedged | no leak detected | `sign`, the default since 2026-08-19 |
| ML-KEM-768 decapsulation | no leak detected | valid against invalid, \|t\| 1.3 |

## Next steps

1. Measure the fixed-round kernel (`sign_deterministic_dangerous`) on both CPUs, on a quiet
   machine.
2. Higher-N dudect runs to bound the residual hedged ML-DSA signal.
3. ML-KEM-768 decapsulation timing on aarch64 (x86-64 done, `examples/dudect_kem.rs`).
4. Make the kernel's acceptance step branch-free, then measure again.
5. **Power/EM trace analysis (CSIT Belfast)**, which software alone cannot do.

Reproduce: `cargo run --release --example dudect_timing`. Raw outputs are in the
`kirq-evidence` pack.
