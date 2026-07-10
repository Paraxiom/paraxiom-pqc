# Side-Channel Audit — paraxiom-pqc signing (timing channel)

A first-pass **timing** side-channel audit of the `paraxiom-pqc` signature
primitives, with a measured mitigation. Power/EM analysis is **out of scope here**
(it needs lab instrumentation — the basis for the planned CSIT Belfast
collaboration); this covers what is measurable in software, on the actual target
silicon.

## Method
`examples/dudect_timing.rs` implements a dudect-style test (Reparaz et al., *"dude,
is my code constant time?"*): for each scheme, interleave two measurement classes —
a **FIXED** secret key vs a pool of **RANDOM** keys — sign a fixed message, time
only the `sign()` call, and run **Welch's t-test** on the two timing populations
with upper-percentile cropping (lower measurements are cleaner). **|t| > 4.5 ⇒
statistically significant key-dependent timing** (≈10⁻⁵ false-positive). SLH-DSA
(hash-based) is the constant-time control that validates the harness.

Run on two CPUs: an x86-64 host and the deployment target — an Arm **Cortex-A53**
(Xilinx Kria KR260).

## Results
**x86-64**
| Scheme / mode | \|t\| | verdict |
|---------------|------:|---------|
| SLH-DSA-128f (control) | 0.66 | clean |
| Falcon-512 | 3.08 | clean |
| **ML-DSA-44 deterministic** | **112.8** | **LEAK** |
| **ML-DSA-44 randomized (hedged)** | **4.4** | clean |

**aarch64 (Cortex-A53, target silicon)**
| Scheme / mode | \|t\| | verdict |
|---------------|------:|---------|
| SLH-DSA-128f (control) | 4.18 | clean |
| Falcon-512 | 3.34 | clean |
| **ML-DSA-44 deterministic** | **98.7** | **LEAK** |
| **ML-DSA-44 randomized (hedged)** | **1.5** | clean |

The leak and its mitigation are **consistent across both CPUs**.

## Finding: deterministic ML-DSA signing leaks key-dependent timing
ML-DSA (Dilithium) signing uses **rejection sampling** — it retries until a
candidate passes the norm bounds. The retry count depends on the key (and message).
With **deterministic** signing (the prior default, `sign_deterministic`), a given
(key, message) always yields the same retry count → a **stable, reproducible
per-key signing time**.

Disambiguation (12 independent keys, deterministic, 3000 signs each): per-key mean
signing time spread **4.8×** (319 µs → 1,536 µs). So the dudect signal is **real
key-dependent timing**, not an unlucky-fixed-key artifact.

Whether timing *alone* enables key recovery is the deeper question (the kind a
power/EM lab resolves) — but a stable per-key timing fingerprint is a measurable
leak that should be removed.

## Mitigation (implemented): hedged / randomized signing
FIPS 204 §3.4 permits **randomized (hedged)** signing — fresh per-signature
randomness. `paraxiom_pqc::sign::sign_randomized()` now provides this for ML-DSA
(via `ml-dsa`'s `sign_randomized`, behind its `rand_core` feature). Falcon is
already randomized and SLH-DSA-*f is timing-flat, so those fall back to `sign`.

Effect: the retry count is now random per signature, so a fixed key's signing time
**varies** instead of being a fingerprint. Measured: the dudect statistic drops
**|t| 112.8 → 4.4** on x86, crossing below the detection threshold.

## ML-KEM-768 decapsulation (valid vs invalid ciphertext)
ML-KEM's Fujisaki-Okamoto transform *implicitly rejects* an invalid ciphertext — it
returns a pseudorandom shared secret instead of erroring. A constant-time decap must
take the **same time** for a valid vs a tampered ciphertext; otherwise decap timing
is a **validity oracle** (a known Kyber/ML-KEM side-channel class). `examples/dudect_kem.rs`
runs the dudect test over interleaved valid vs invalid (one flipped byte) ciphertexts:

| Ciphertext | decap time (x86) |
|------------|------------------|
| valid | ~137.0 µs |
| invalid (tampered) | ~137.0 µs |
| **dudect statistic** | **\|t\| = 1.3** |

**Result: constant-time — no validity timing oracle** (|t|=1.3, well below the 4.5
threshold). The FO implicit-rejection path does not leak ciphertext validity via
timing on x86; the aarch64 measurement is the follow-up.

- ML-KEM decap timing — `measured (evidence: sidechannel-mlkem-decap-x86.txt)`

## Honest limits
- **Timing channel only.** Power and EM side-channels are *not* covered here and
  may leak where timing does not — that is the explicit purpose of the CSIT lab.
- **Randomization removes the per-signature fingerprint, not the inherent
  data-dependence.** The *expected* retry count is still key-dependent; |t|=4.4 is
  just below threshold at N≈10⁴ and may rise at higher N. True constant-time needs
  constant-time rejection sampling — deeper work.
- **Falcon showed no mean-timing leak** here, but its floating-point Gaussian
  sampler remains the classic power/EM concern; no *timing* signal ≠ no side-channel.
- Backend crates (`ml-kem`/`ml-dsa`/`slh-dsa`, RustCrypto) are pre-release (rc.*).

## Posture summary
| Primitive | timing (this audit) | notes |
|-----------|---------------------|-------|
| SLH-DSA-Shake128f | constant-time | hash-based; control |
| Falcon-512 | no timing leak detected | FP sampler — power/EM TBD |
| ML-DSA (deterministic) | **leaks** | rejection sampling |
| ML-DSA (randomized) | mitigated | use `sign_randomized` |
| ML-KEM-768 decap | constant-time | valid vs invalid \|t\|=1.3 — FO implicit-rejection clean |

## Next steps
1. Higher-N dudect to bound the residual ML-DSA signal.
2. ML-KEM-768 decap timing on aarch64 (x86 done — constant-time, `examples/dudect_kem.rs`).
3. Constant-time rejection sampling for ML-DSA.
4. **Power/EM trace analysis (CSIT Belfast)** — the part software alone cannot do.

Reproduce: `cargo run --release --example dudect_timing`. Raw outputs are in the
`kirq-evidence` pack.
