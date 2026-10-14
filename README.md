# paraxiom-pqc

**Post-quantum cryptography in pure Rust, with no C code.**

One API for four NIST post-quantum algorithms, three of them published standards:

| Standard | Algorithm | Parameter sets |
|---|---|---|
| **FIPS 203** | ML-KEM | 512, 768, 1024 |
| **FIPS 204** | ML-DSA | 44, 65, 87 |
| **FIPS 205** | SLH-DSA | SHAKE-128f, SHAKE-256s |
| **FIPS 206** (draft) | Falcon (FN-DSA) | 512, 1024 |

> FN-DSA (FIPS 206) is not yet a final NIST standard. Deployments that need a final signature
> standard today should use ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), or pair Falcon with one of
> them.

## Usage

```rust
use paraxiom_pqc::kem::{keypair, encapsulate, decapsulate, KemAlgorithm};
use paraxiom_pqc::sign::{keypair as sign_keypair, sign, verify, SignAlgorithm};

// ML-KEM key exchange
let kp = keypair(KemAlgorithm::MlKem1024).unwrap();
let (ct, ss_enc) = encapsulate(&kp.ek).unwrap();
let ss_dec = decapsulate(&kp.dk, &ct).unwrap();
assert_eq!(ss_enc.bytes, ss_dec.bytes);

// ML-DSA signing (hedged, the default)
let kp = sign_keypair(SignAlgorithm::MlDsa65).unwrap();
let sig = sign(&kp.sk, b"message").unwrap();
assert!(verify(&kp.vk, b"message", &sig).unwrap());
```

### Key combiner (feature `combiner`)

Combines a QKD key, ML-KEM shared secrets or a pre-shared key into one 32-byte key bound to a
transcript. The mechanism set is a per-link policy, and a missing or reordered input is refused
(fail closed). The output stays secret as long as at least one input does.

```rust
use paraxiom_pqc::combiner::{Mechanism, Policy, Secret};

let policy = Policy::new(&[Mechanism::Qkd, Mechanism::MlKem768]).unwrap();
let key = policy.combine(
    &[Secret::new(Mechanism::Qkd, &qkd_key), Secret::new(Mechanism::MlKem768, &ss_enc.bytes)],
    &transcript_hash,
).unwrap();
```

`combiner::qkd_pqc_v2` reproduces the QKD + PQC mixing used by pq-transport-gateway byte for byte.

## Key handling

- Secret material is cleared from memory when it is dropped. `kem::DecapsulationKey`,
  `kem::SharedSecret` and `sign::SigningKey` implement `ZeroizeOnDrop` (the `zeroize` crate), and
  the ML-KEM, ML-DSA and SLH-DSA backends are built with their `zeroize` feature; falcon-rs clears
  its keys itself. Copies that the compiler makes on the stack, and intermediate values inside the
  algorithms, are not covered.
- Because of that `Drop` impl, `bytes` cannot be moved out of those three types (since 0.2.0).
  Borrow it, clone it, or take it with `std::mem::take(&mut key.bytes)`.
- `kem::DecapsulationKey.bytes` is the 64-byte FIPS 203 seed `d || z` for all three parameter
  sets. An ML-DSA `sign::SigningKey` holds the 32-byte FIPS 204 seed.
- The `qrng` feature conditions entropy from a `qrng::QuantumSource` that you implement over your
  hardware. The crate ships no source.

## Signing notes

- **ML-DSA.** `sign` uses the hedged (randomized) mode of FIPS 204.
  `sign_deterministic_dangerous` runs a fixed-round kernel (814 rounds, the lowest loop limit
  FIPS 204 allows) that has never been timing-measured and is not fully constant time. Read its
  documentation and `WP2_TIMING_ORACLE_MITIGATION.md` before using it.
- **Falcon.** falcon-rs computes key generation and signing in floating point on secret values.
  They are built only on x86/x86_64 with SSE2 and AArch64 with NEON, where all of it runs in
  hardware. On other targets `keypair` and `sign` return an error for Falcon and
  `sign::FALCON_SIGNING_AVAILABLE` is false. Verification uses integer arithmetic and works
  everywhere, including with the `falcon-verify` feature alone. Signatures use falcon-rs's FN-DSA
  framing and fixed-length encoding (809 bytes for Falcon-512), which differs from the round 3
  format and may change when FIPS 206 is final.
- Timing measurements are in `docs/SIDE-CHANNEL-AUDIT.md`. They cover the timing channel only.

## Security status

This code has not been externally audited. The algorithm crates (`ml-kem`, `ml-dsa`, `slh-dsa`)
are pre-release versions whose authors state they have never been independently audited, and
`ml-dsa` and `slh-dsa` are vendored here with local changes (`vendor/`). See `SECURITY.md`.

## Why This Exists

The PQC ecosystem is fragmented: `pqcrypto-*` crates wrap C code from PQClean, `ml-kem`/`ml-dsa`/`slh-dsa` are separate crates with incompatible `rand_core` versions, and `falcon-rs` has its own API. `paraxiom-pqc` puts them behind one API with no C dependencies.

## Lean model

`lean/ParaxiomPQC.lean` holds 30 Lean 4 theorems (Mathlib v4.27.0, no `sorry`) about a
hand-written model of the API: parameter, key and signature sizes, algorithm dispatch, and
correctness statements that hold by definition or assume the scheme is correct. They do not
verify the Rust code or any security property. The zero-C theorem checks a hand-written list of
dependency names; the dependency tree itself is checked with `cargo tree`.

`lean/Combiner.lean` (core Lean) proves that the combiner's input encoding is injective, so two
different input lists never hash the same bytes.

An earlier version of the Lean files was published as
[DOI 10.5281/zenodo.18663125](https://doi.org/10.5281/zenodo.18663125).

## Tests

`cargo test --all-features` runs round trips and tamper checks for every parameter set, the
combiner vectors (including cross-implementation vectors from pq-transport-gateway), QRNG
seeding, a fixed Falcon-512 verification vector, the Falcon target guard, and checks that secret
buffers are zero when their memory is freed. The vendored ML-DSA fork has its own tests:
`cargo test -p ml-dsa --all-features` (its pkcs8 test needs `RUST_MIN_STACK=16777216` in debug
builds).

`tests/acvp.rs` runs subsets of the NIST ACVP vectors for ML-KEM, ML-DSA and SLH-DSA
(SHAKE-128f and SHAKE-256s): key generation, encapsulation, decapsulation including modified
ciphertexts, the encapsulation-key check, deterministic and hedged signing (the fixed-round
ML-DSA kernel included) and verification. `tests/acvp/README.md` gives the source commit, the
selection rules and what each test checks. Falcon has no ACVP vectors yet.

## License

**GPL-3.0-only**, or a **Paraxiom commercial licence**, at your option (see `LICENSING.md`).

Free under GPL-3.0 for research, evaluation and open-source products. Embedding in a
**proprietary** product requires a commercial licence: sylvain@paraxiom.org

Releases published before 8 August 2026 were under `MIT OR Apache-2.0`; that change is
not retroactive.

## Contact

Sylvain Cormier, [Paraxiom Technologies Inc.](https://paraxiom.org), Montreal
