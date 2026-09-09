//! # paraxiom-pqc
//!
//! Pure Rust post-quantum cryptography. Zero C code.
//!
//! Unified API for:
//! - **ML-KEM** (FIPS 203) — Key encapsulation
//! - **ML-DSA** (FIPS 204) — Digital signatures (lattice-based)
//! - **SLH-DSA** (FIPS 205) — Digital signatures (hash-based, stateless)
//! - **Falcon** (pending FIPS 206) — Digital signatures (lattice-based, compact)

#[cfg(feature = "sign")]
pub mod dsa_ct;
pub mod error;
pub mod kem;
#[cfg(feature = "qrng")]
pub mod qrng;
#[cfg(feature = "sign")]
pub mod sign;

pub use error::PqcError;
