# Security Policy

## Reporting a Vulnerability

Paraxiom takes the security of its post-quantum cryptography seriously.

If you discover a security vulnerability in `paraxiom-pqc`, please report it
**privately; do not open a public issue**.

- Email: **security@paraxiom.org** (or sylvain@paraxiom.org)
- Please include a description, the affected version, and reproduction steps.

We aim to acknowledge reports within 5 business days and to provide a
remediation timeline after triage. Coordinated disclosure is appreciated.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Scope & Cryptographic Note

`paraxiom-pqc` is a pure-Rust (zero C/C++) library exposing NIST PQC
algorithms: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and
Falcon. It depends on upstream pre-release (`rc.*`) implementation crates
pinned to exact versions; algorithm-level correctness ultimately rests on
those upstreams.

Please report issues in the unified API, key handling, zeroization, or
misuse-resistance here. Issues in the underlying algorithm implementations may
additionally warrant a report to the corresponding upstream crate.

## Status

- `paraxiom-pqc` has not been externally audited. The timing measurements in
  `docs/SIDE-CHANNEL-AUDIT.md` are internal and cover the timing channel only.
- Secret keys and shared secrets are cleared on drop: the library's own key
  types and the backend key structs. Copies the compiler makes on the stack and
  intermediate values inside the algorithms are not covered.
- Falcon key generation and signing are built only on x86/x86_64 with SSE2 and
  AArch64 with NEON, where falcon-rs's floating point runs in hardware.
  Elsewhere they return an error; verification works on every target.
- The deterministic ML-DSA path (`sign_deterministic_dangerous`) runs a
  fixed-round kernel that has not been timing-measured and is not fully
  constant time. See `WP2_TIMING_ORACLE_MITIGATION.md`.
