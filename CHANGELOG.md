# Changelog

## 0.2.1 (2026-11-04)

Two pinned dependencies move forward, one test is adapted to the new ML-KEM key layout, and one
test is added. The crate's code and public API are unchanged; one doc comment in `src/sign.rs`
now names falcon-rs 0.3.1.

### Security

- ml-kem 0.3.0-rc.0 to 0.3.3 (pinned `=0.3.3`). In 0.3.0-rc.0, CBD sampling, used in key
  generation, encapsulation and decapsulation, read a small table at an index taken from secret
  bits: a cache-timing side channel. ml-kem 0.3.3 computes each coefficient arithmetically
  instead (RustCrypto/KEMs #386), and its maintainers list the change under Security. This crate
  rebuilds the ML-KEM key from its seed on every `kem::decapsulate` call, so under 0.2.0 that
  lookup ran on the long-term secret once per decapsulation. The pin also moves ML-KEM from a
  release candidate to a release.
- ml-kem 0.3.3 depends on module-lattice 0.2, which resolves to 0.2.4, in this repository's
  `Cargo.lock` and in a fresh resolve. 0.2.4 computes its modular reduction with ctutils's
  constant-time comparison and selection (RustCrypto/KEMs #409). module-lattice 0.1.0, which
  0.2.0 used, wrote that reduction as a branch in the source.
- ml-kem 0.3.4 (2026-10-31) is not taken. It requires Rust 1.87, so users on Rust 1.85 could not
  take this release at all and would stay on 0.3.0-rc.0. Its fixes are in code this crate does
  not call (printing a key with `Debug`, comparing keys, PKCS#8 encoding, importing an expanded
  key), and its other change speeds up a step that works on public data.
- falcon-rs 0.2.3 to 0.3.1 (pinned `=0.3.1`; 0.3.0 has the code changes, 0.3.1 changes only
  documentation). Signing now checks each new signature against the public key before returning
  it. A signature that fails the check is discarded: `sign::sign` and the other signing
  functions return `PqcError::Sign` with the text `FaultDetected`, which should be treated as a
  security event, not retried. falcon-rs 0.3.1 also wipes more of its signing buffers, but not
  all of them: the raw signature vector is freed without being cleared, so after a detected
  fault the discarded signature stays in freed memory. falcon-rs's opt-in integer emulation of
  floating point (`fpemu`, which its author describes as constant time) is not enabled here, so
  Falcon key generation and signing still use hardware floating point, and
  `sign::FALCON_SIGNING_AVAILABLE` is unchanged.

### Performance

Measured through this crate's API on one Apple M1 Max (aarch64-apple-darwin), release builds,
medians of runs alternating between 0.2.0 and 0.2.1. x86_64 was not measured.

- ML-KEM takes about 30 to 50 percent longer. ML-KEM-768 on that machine: key generation 33 to
  44 microseconds, encapsulation 31 to 45, decapsulation 67 to 92. The cost comes from
  module-lattice 0.2.4's constant-time reduction: built with module-lattice 0.2.3 instead,
  ML-KEM-768 decapsulation takes about 43 microseconds, less than under 0.2.0. This release
  keeps 0.2.4, trading that speed for the hardened reduction.
- Falcon-512 signing takes about 15 percent longer (314 to 363 microseconds), from falcon-rs's
  signature check and wiping. falcon-rs's README puts these at about 10 percent for the check
  and about 16 percent more for the wiping, against its 0.2.x baseline.

### Dependency graph

- New: module-lattice 0.2.4, sha3 0.12.0, shake 0.1.0 and sponge-cursor 0.1.0. ctutils moves
  from 0.4.2 to 0.4.8, and subtle is no longer used. None of them compiles or binds C (checked by
  `scripts/check-zero-c.sh` in the repository).

### Minimum Rust version

- With this repository's `Cargo.lock`: 1.87, up from 1.85 with 0.2.0's. ml-kem 0.3.3 needs
  1.85, but module-lattice 0.2.4 and ctutils 0.4.8, to which cargo resolves its dependencies,
  declare 1.87. In this repository, Rust 1.85 builds the library and its tests after
  `cargo update -p module-lattice@0.2.4 --precise 0.2.3` and
  `cargo update -p ctutils --precise 0.4.2`.
- A crate that depends on paraxiom-pqc resolves its own versions, so these figures do not carry
  over. A fresh resolve today also takes sha2 0.11.1 (through paraxiom-slh-dsa, with the
  default `sign` feature), which declares 1.88. On Rust 1.85, either let cargo's MSRV-aware
  resolver choose (set `package.rust-version = "1.85"` and `resolver = "3"`), or run the two
  commands above and `cargo update -p sha2@0.11.1 --precise 0.11.0`.
- module-lattice 0.2.3 writes the reduction with a bit mask rather than through ctutils (see
  Security and Performance).

### Tests

- `tests/zeroize.rs`: since ml-kem 0.3.2 the ML-KEM decapsulation key keeps d, z, the secret
  vector s_hat and the public encryption key in four separate heap allocations, not inside the
  key struct, so the old check, which looked for the secrets inside the boxed key, failed before
  the drop. The test now records the allocations the key makes, checks that d, z and s_hat each
  sit in an allocation of their own, and checks that each of those is all zero when freed. Two
  controls show that the check can fail: a copy of d in an allocation of the same kind, freed
  without being cleared, must be reported as still holding d, and the allocation holding the
  public encryption key, which ml-kem does not clear, must be reported as still holding rho.
  With ml-kem's `zeroize` feature turned off, the test fails on the wipe check. It covers the
  key's own allocations, checked when the key is dropped.
- `tests/zeroize_freed_heap.rs` (new): while one call runs, it copies every buffer the call
  frees, just before the buffer goes back to the allocator, then searches the copies for
  secrets. This covers temporary copies, which `tests/zeroize.rs` does not see. ML-KEM key
  generation, encapsulation and decapsulation (of a valid and of a modified ciphertext) are
  searched for d, z, windows of s_hat, the message and the shared secret; Falcon key generation
  and signing for windows of the encoded private key. None is found with ml-kem 0.3.3 and
  falcon-rs 0.3.1. The test fails on two modified copies of ml-kem 0.3.3: one frees an unwiped
  copy of the key while building it, the other while decapsulating. In a release build the
  compiler removes the first copy, which nothing reads, so no secret reaches the heap and the
  test rightly finds none; the second copy is used, and the test fails on it in both builds.

### Packaging

- `.github/`, which 0.2.0 shipped, is now left out of the published crate, and so is `scripts/`:
  both hold files for the repository's own checks.

### Other

- `kani/Cargo.lock` follows the new versions. It had also still named the vendored ML-DSA and
  SLH-DSA crates by their upstream names. It is not part of the published crate.
- README.md, SECURITY.md and docs/SIDE-CHANNEL-AUDIT.md no longer call ml-kem a pre-release,
  and the timing document says that its ML-KEM and Falcon rows were measured on the old
  versions.

## 0.2.0 (2026-10-15)

0.2.0 rather than 0.1.5 because some changes break callers at compile time, on purpose, and
some change what is accepted at run time.

### Packaging

- The vendored ML-DSA and SLH-DSA code is published under its own names,
  `paraxiom-ml-dsa` (from RustCrypto ml-dsa 0.1.0-rc.7) and `paraxiom-slh-dsa` (from
  RustCrypto slh-dsa 0.2.0-rc.4), pinned with `=` versions. Inside the crate they keep the
  names `ml_dsa` and `slh_dsa`. Without this, a crates.io build would resolve upstream
  ml-dsa and lose the zeroization and fixed-round signing changes.

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
