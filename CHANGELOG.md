# Changelog

## 0.2.0 (unreleased)

0.2.0 rather than 0.1.5 because some changes break callers at compile time, on purpose, and
some change what is accepted at run time.

### Breaking: compile time

- `kem::DecapsulationKey`, `kem::SharedSecret` and `sign::SigningKey` now implement `Drop`
  (`ZeroizeOnDrop`), so their `bytes` field can no longer be moved out: code such as
  `let seed = keypair.sk.bytes;` or `let key = shared_secret.bytes;` fails with E0509.
  Borrowing, cloning, struct literals and in-place changes still compile. Fix: borrow
  (`&sk.bytes`), clone, or `std::mem::take(&mut sk.bytes)`. Known affected caller: the
  QuantumHarmony node, `node/src/quantum_p2p/identity.rs`, which returns
  `shared_secret.bytes` by move after `kem::encapsulate` and after `kem::decapsulate`.
- `qrng::TestQuantumSource` (a non-cryptographic xorshift generator) is removed from the
  library. Tests that need a deterministic source must define their own.

### Breaking: run time

- Falcon `keypair`, `sign`, `sign_randomized` and `sign_deterministic_dangerous` return an error
  on targets other than x86/x86_64 with SSE2 and AArch64 with NEON, where falcon-rs's floating
  point on secret values would run in software. Verification works on every target. New
  constant: `sign::FALCON_SIGNING_AVAILABLE`.
- Falcon verification now checks the degree. `falcon::verify` accepts only Falcon-512 keys
  (header 0x09, 897 bytes) and Falcon-1024 keys (header 0x0A, 1793 bytes); before, it accepted
  every degree falcon-rs parses, n = 2 to 1024, including toy degrees with no security.
  `sign::verify` returns `Ok(false)` when the key's degree is not the one its label
  (`SignAlgorithm::Falcon512` or `Falcon1024`) names; before, a key labelled Falcon-1024
  accepted Falcon-512 signatures. `sign::sign` (and the other signing functions) refuse a Falcon
  signing key whose header and length do not match its label. Callers that labelled keys of one
  degree with the other must fix the label. Present in every release since the initial public
  release (9c821a9), including 0.1.0 to 0.1.3 on crates.io and git 0.1.4: `sign::verify`
  passed Falcon keys to falcon-rs with no degree or label check from the start, and the
  `falcon-verify` feature (a54d439) added `falcon::verify` with the same gap. Known 0.1.3 user:
  pq-transport-gateway (pinned at git c0ee1f7), whose Falcon keys are pinned or allow-listed by
  the operator and labelled Falcon-512, so its exposure is low.
- `sign_deterministic_dangerous` for ML-DSA runs its fixed-round kernel for 814 rounds, the
  lowest loop limit FIPS 204 allows, instead of 256. Signatures are the same; signing is about
  3.2 times slower. The documentation now gives the failure probability of the kernel (about
  2^-315, 2^-256 and 2^-353 for ML-DSA-44, -65 and -87); the earlier "< 2^-128" figure for 256
  rounds was wrong (it was about 2^-81 to 2^-111).

### Fixed

- Secret keys and shared secrets are cleared from memory when dropped. The ML-KEM, ML-DSA and
  SLH-DSA backends are built with their `zeroize` feature (the vendored ML-DSA fork's `zeroize`
  feature did not compile before), and the fork's `SigningKey` fields are private again.
- ML-DSA verification no longer reads the OS random number generator.
- The `dudect_timing` example measures the deterministic ML-DSA path again (it had been
  measuring the hedged one).
- Documentation: the ML-KEM decapsulation key is the 64-byte seed `d || z`, not 32 bytes (Rust
  docs and the Lean model); the claim that the code was audited is removed (it has not been
  externally audited).

### Added

- NIST ACVP vector tests for ML-KEM, ML-DSA and SLH-DSA (`tests/acvp.rs`).
- Property tests (`tests/properties.rs`), run-time zeroization checks with a watching allocator
  (`tests/zeroize.rs`), cargo-fuzz targets (`fuzz/`) and Kani harnesses (`kani/`). See the README
  for what each covers. None of this is an audit or a proof of the cryptographic code.

### Supported versions

0.1.x is no longer supported: it does not clear secret keys from memory, and its Falcon
verification does not check the degree.
