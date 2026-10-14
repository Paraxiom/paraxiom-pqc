//! # paraxiom-pqc
//!
//! Post-quantum cryptography in pure Rust, with no C code.
//!
//! One API for:
//! - **ML-KEM** (FIPS 203): key encapsulation
//! - **ML-DSA** (FIPS 204): lattice-based signatures
//! - **SLH-DSA** (FIPS 205): stateless hash-based signatures
//! - **Falcon** (FIPS 206, still a draft): compact lattice-based signatures
//!
//! Secret keys and shared secrets are cleared from memory when they are dropped. Falcon key
//! generation and signing are built only on x86/x86_64 with SSE2 and AArch64 with NEON
//! (`sign::FALCON_SIGNING_AVAILABLE`); Falcon verification works on every target.
//!
//! This code has not been externally audited.

#[cfg(feature = "sign")]
mod dsa_ct;
#[cfg(feature = "combiner")]
pub mod combiner;
pub mod error;
#[cfg(any(feature = "sign", feature = "falcon-verify"))]
pub mod falcon;
pub mod kem;
#[cfg(feature = "qrng")]
pub mod qrng;
#[cfg(feature = "sign")]
pub mod sign;

pub use error::PqcError;
