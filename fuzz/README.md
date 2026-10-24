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
made 185 runs in 61 s (its input-seeded version, 2026-10-24) and `slh_dsa_signing_key` 103 runs in
64 s, with no failure. Fuzz the SLH-DSA
targets for hours, not minutes.

## Targets

"Proof candidate" refers to the halts statement of OSS Verify (theorem-labs/oss-verify): on every
input under 64 MiB, a static RISC-V build exits normally, with no crash, hang, failed assertion
or sanitizer detection. A target that checks a property then proves that property for every
such input. "Plausible" means only that the code these targets reach has bounded loops: nothing
here has yet been built for static riscv64 or run through their pipeline.

| Target | Property checked | Proof candidate as written |
|---|---|---|
| `combiner` | The combiner's output equals the documented encoding, hashed independently with SHA3-256; secrets that do not match the policy are refused | plausible: only bounded loops found (SHA3, loops over the input) |
| `slh_dsa_verify` | Any key, signature and message: verification never accepts wrong lengths and never panics | plausible: only bounded loops found (SLH-DSA has fixed iteration counts) |
| `slh_dsa_signing_key` | SLH-DSA alone: a signing key of the wrong length is refused; a signature has the FIPS 205 length | plausible: only bounded loops found |
| `slh_dsa_roundtrip` | A key pair derived from the input (FIPS 205 key generation) signs the rest of the input; the signature verifies; signing twice gives the same bytes | plausible: only bounded loops found, and every random value comes from the input |
| `kem_encapsulation_key` | Acceptance equals the FIPS 203 section 7.2 check, written independently | no: unbounded sampling, and encapsulation reads the OS random source; see below |
| `kem_decapsulate` | Acceptance exactly when the lengths are right; the secret is 32 bytes | no, see below |
| `ml_dsa_verify` | Verification accepts only the right lengths | no, see below |
| `signing_key` | Any signing key for any algorithm: lengths, labels, Falcon headers | no: hedged ML-DSA signing, `sign_randomized` and Falcon read the OS random source, and ML-DSA samples without bound. Its SLH-DSA part is `slh_dsa_signing_key` |
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

## Randomness comes from the input

OSS Verify runs a target as one thread whose only data is its input: no clock, no network, no
environment and no random numbers. A target that draws from the OS random source is therefore
outside what can be proved, or its property becomes vacuous. `slh_dsa_roundtrip` derives its key
pair from the input for this reason. `kem_encapsulation_key` (encapsulation draws its message
from the OS) and `signing_key` (hedged and randomized signing) still do; making them
deterministic needs seeded entry points in the library, which is a decision for the library.

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
`slh_dsa_roundtrip` crash, hang or fail a check; so for every key pair generated from such an
input, the SLH-DSA-SHAKE-128f signature of the rest of the input verifies, and signing is
deterministic." Not "formally verified", and nothing about
constant time or the other algorithms.
