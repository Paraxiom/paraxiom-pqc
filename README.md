# paraxiom-pqc

**Pure Rust post-quantum cryptography. Zero C code.**

Unified API for all four NIST PQC standards:

| Standard | Algorithm | Levels |
|---|---|---|
| **FIPS 203** | ML-KEM | 512, 768, 1024 |
| **FIPS 204** | ML-DSA | 44, 65, 87 |
| **FIPS 205** | SLH-DSA | SHAKE-128f, SHAKE-256s |
| **FIPS 206** | Falcon | 512, 1024 |

## Usage

```rust
use paraxiom_pqc::kem::{keypair, encapsulate, decapsulate, KemAlgorithm};
use paraxiom_pqc::sign::{keypair as sign_keypair, sign, verify, SignAlgorithm};

// ML-KEM key exchange
let kp = keypair(KemAlgorithm::MlKem1024).unwrap();
let (ct, ss_enc) = encapsulate(&kp.ek).unwrap();
let ss_dec = decapsulate(&kp.dk, &ct).unwrap();
assert_eq!(ss_enc.bytes, ss_dec.bytes);

// Falcon signing
let kp = sign_keypair(SignAlgorithm::Falcon512).unwrap();
let sig = sign(&kp.sk, b"message").unwrap();
assert!(verify(&kp.vk, b"message", &sig).unwrap());
```

## Why This Exists

The PQC ecosystem is fragmented: `pqcrypto-*` crates wrap C code from PQClean, `ml-kem`/`ml-dsa`/`slh-dsa` are separate crates with incompatible `rand_core` versions, and `falcon-rs` has its own API. `paraxiom-pqc` unifies them behind one API with zero C dependencies.

## Formal Verification

30 Lean 4 theorems (Mathlib v4.27.0, zero sorries) covering:
- KEM correctness and shared secret agreement
- Signature correctness and tamper detection
- Algorithm dispatch totality
- FIPS standard coverage completeness
- Zero-C dependency verification

Published: [DOI 10.5281/zenodo.18663125](https://doi.org/10.5281/zenodo.18663125)

## Tests

13 tests covering all 10 algorithm variants. All pass.

## License

**GPL-3.0-only**, or a **Paraxiom commercial licence**, at your option — see `LICENSE.md`.

Free under GPL-3.0 for research, evaluation and open-source products. Embedding in a
**proprietary** product requires a commercial licence: sylvain@paraxiom.org

Releases published before 8 August 2026 were under `MIT OR Apache-2.0`; that change is
not retroactive.

## Contact

Sylvain Cormier — [Paraxiom Technologies Inc.](https://paraxiom.org) — Montreal
