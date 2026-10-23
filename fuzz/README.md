# Fuzz targets

cargo-fuzz harnesses for paraxiom-pqc. Each target aborts when the property it states is false,
so a target that never aborts checks that property on every input it is given.

## Running

```sh
# rustup's toolchains must come before Homebrew's Rust, if both are installed
export PATH="$HOME/.cargo/bin:$PATH"
cd fuzz && cargo +nightly run --bin gen_corpus && cd ..   # seed inputs: real keys, ciphertexts, signatures
cargo +nightly fuzz run <target> -- -max_total_time=600
```

SLH-DSA is slow under AddressSanitizer: on 2026-10-23 on this Mac (aarch64), `slh_dsa_roundtrip`
made 184 runs in 62 s and `slh_dsa_signing_key` 103 runs in 64 s, with no failure. Fuzz the SLH-DSA
targets for hours, not minutes.

## Targets

"Proof candidate" refers to the halts statement of OSS Verify (theorem-labs/oss-verify): on every
input under 64 MiB, a static RISC-V build exits normally, with no crash, hang, failed assertion
or sanitizer detection. A target that checks a property then proves that property for every
such input.

| Target | Property checked | Proof candidate as written |
|---|---|---|
| `combiner` | The combiner's output equals the documented encoding, hashed independently with SHA3-256; secrets that do not match the policy are refused | yes: SHA3 and loops bounded by the input |
| `slh_dsa_verify` | Any key, signature and message: verification never accepts wrong lengths and never panics | yes: SLH-DSA has fixed iteration counts |
| `slh_dsa_signing_key` | SLH-DSA alone: a signing key of the wrong length is refused; a signature has the FIPS 205 length | yes |
| `slh_dsa_roundtrip` | A fresh key pair signs the input; the signature verifies; signing twice gives the same bytes | yes. Key generation reads the OS random source, and the statement covers every OS response |
| `kem_encapsulation_key` | Acceptance equals the FIPS 203 section 7.2 check, written independently | no, see below |
| `kem_decapsulate` | Acceptance exactly when the lengths are right; the secret is 32 bytes | no, see below |
| `ml_dsa_verify` | Verification accepts only the right lengths | no, see below |
| `signing_key` | Any signing key for any algorithm: lengths, labels, Falcon headers | not as a whole; its SLH-DSA part is `slh_dsa_signing_key` |
| `falcon_verify` | The direct Falcon API and `sign::verify` agree | probably not, see below |

## Why some targets are not proof candidates as written

A halts proof must show that every loop ends on every input. Rejection sampling over SHAKE output
ends only when the hash supplies enough acceptable values, and nothing bounds that for all inputs:

- ML-KEM: `ml-kem` 0.3.0-rc.0, `src/algebra.rs:63`, an unbounded `loop` in the sampler that
  expands the matrix from the key's `rho`. Encapsulation and decapsulation both run it.
- ML-DSA: `vendor/ml-dsa-fork/src/sampling.rs:85` (sampling the challenge from the signature's
  `c~`) and `:109` (rejection sampling of the matrix from the key's `rho`).
- Falcon: `falcon-rs` 0.2.3, `src/common.rs:14`, `hash_to_point_vartime` rejects values from
  61445 up. Which hash-to-point variant verification calls is still to confirm.

The ML-DSA signing loop is bounded: `vendor/ml-dsa-fork/src/lib.rs:391` stops at `u16::MAX`, and
the fixed-round kernel runs the 814 rounds of FIPS 204 Appendix C, Table 3. Appendix C is where
any limit on the sampling loops would also come from. Bounding them is a library decision and is
not made here.

## Left out on purpose

- **A KEM round trip.** `tests/properties.rs` covers it with proptest. "Decapsulation always
  recovers the encapsulated secret" is not a theorem: ML-KEM's decryption failure rate is tiny but
  not zero, so no halts proof of that assertion can exist.
- **Unforgeability.** Another message or a changed signature verifying is infeasible, not
  impossible, so no target asserts that it never happens.

## An observation

`sign::verify` chooses the algorithm from the verification key and does not compare the
signature's `algorithm` label: `slh_dsa_verify` parses the signature bytes with the key's
parameter set. This does not help a forger, but a caller who reads the label could be misled.
Whether a mismatched label should be refused is a decision for the library.

## How to describe a result

Say exactly what was proved, for example: "On static RISC-V builds, no input under 64 MiB makes
`slh_dsa_roundtrip` crash, hang or fail a check; so every fresh SLH-DSA-SHAKE-128f signature of
such a message verifies, and signing is deterministic." Not "formally verified", and nothing about
constant time or the other algorithms.
