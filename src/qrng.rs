//! Optional quantum-RNG entropy source — feature `qrng`, **default OFF**.
//!
//! Seeds post-quantum key generation from a pluggable *quantum* entropy source
//! (real QKD/QRNG hardware in deployment; a deterministic test source for CI).
//!
//! ## Honesty & scope (read before quoting this anywhere)
//! - This is **entropy-source assurance and defense-in-depth**, *not* a claim
//!   that quantum-random keys are cryptographically stronger. A well-seeded
//!   classical CSPRNG is already sufficient; NIST does **not** require quantum
//!   entropy, and ML-KEM/ML-DSA security does not improve because the seed came
//!   from a photon. The value is for buyers who will not trust the *OS* RNG
//!   (compromised host, thin-entropy VM, certification requirements).
//! - Raw quantum output is **never used directly**. It seeds a SHAKE256-
//!   conditioned CSPRNG ([`QrngRng`]). Production should validate the
//!   conditioner against NIST SP 800-90B and consider a certified SP 800-90A
//!   DRBG; the construction here is a vetted-XOF (SHAKE256) conditioner.

use crate::error::PqcError;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroize;

const KEY_LEN: usize = 32;
const RESEED_INTERVAL: usize = 1 << 20; // reseed after ~1 MiB of output

/// A raw quantum entropy source. Implemented by QKD/QRNG hardware; see
/// [`TestQuantumSource`] for a CI stand-in. Output is conditioned by
/// [`QrngRng`] and never consumed raw.
pub trait QuantumSource {
    /// Fill `dest` with raw quantum entropy. May fail (hardware / link down).
    fn fill_entropy(&mut self, dest: &mut [u8]) -> Result<(), PqcError>;
}

/// A CSPRNG seeded (and periodically reseeded) from a [`QuantumSource`],
/// conditioned through SHAKE256. Infallible once constructed. Implements
/// rand_core's `Rng`/`CryptoRng` (via `TryRng<Error = Infallible>`), so it drops
/// straight into the `*_qrng` key-generation APIs and hedged signing.
pub struct QrngRng<S: QuantumSource> {
    source: S,
    key: [u8; KEY_LEN],
    counter: u64,
    bytes_since_reseed: usize,
}

impl<S: QuantumSource> QrngRng<S> {
    /// Seed a fresh DRBG from the quantum source. Fails only if the source fails.
    pub fn new(mut source: S) -> Result<Self, PqcError> {
        let mut raw = [0u8; 64];
        source.fill_entropy(&mut raw)?;
        let mut key = [0u8; KEY_LEN];
        let mut h = Shake256::default();
        h.update(b"paraxiom-pqc/qrng/v1/seed");
        h.update(&raw);
        h.finalize_xof().read(&mut key);
        raw.zeroize();
        Ok(Self {
            source,
            key,
            counter: 0,
            bytes_since_reseed: 0,
        })
    }

    /// Fill `dest` with conditioned quantum-seeded pseudorandom bytes.
    pub fn fill(&mut self, dest: &mut [u8]) {
        let mut h = Shake256::default();
        h.update(b"paraxiom-pqc/qrng/v1/gen");
        h.update(&self.key);
        h.update(&self.counter.to_le_bytes());
        h.finalize_xof().read(dest);
        self.counter = self.counter.wrapping_add(1);
        self.bytes_since_reseed = self.bytes_since_reseed.saturating_add(dest.len());
        if self.bytes_since_reseed >= RESEED_INTERVAL {
            self.reseed();
        }
    }

    fn reseed(&mut self) {
        // Best-effort: mix fresh quantum entropy into the key. A CSPRNG stays
        // secure without reseeding, so a source failure here is non-fatal.
        let mut raw = [0u8; 64];
        if self.source.fill_entropy(&mut raw).is_ok() {
            let mut h = Shake256::default();
            h.update(b"paraxiom-pqc/qrng/v1/reseed");
            h.update(&self.key);
            h.update(&raw);
            let mut nk = [0u8; KEY_LEN];
            h.finalize_xof().read(&mut nk);
            self.key.zeroize();
            self.key = nk;
        }
        raw.zeroize();
        self.bytes_since_reseed = 0;
    }
}

impl<S: QuantumSource> Drop for QrngRng<S> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// rand_core 0.10: implementing `TryRng` with `Error = Infallible` yields
// `Rng`/`CryptoRng`/`TryCryptoRng` via the blanket impls (same pattern as the
// getrandom-backed `OsGetRandom` in `sign.rs`).
impl<S: QuantumSource> rand_core::TryRng for QrngRng<S> {
    type Error = rand_core::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dst);
        Ok(())
    }
}
impl<S: QuantumSource> rand_core::TryCryptoRng for QrngRng<S> {}

/// **TEST ONLY** deterministic stand-in for a quantum source (seeded xorshift).
/// NOT cryptographically secure — it exists so CI can exercise the conditioning
/// pipeline reproducibly. Real deployments implement [`QuantumSource`] over QKD
/// / QRNG hardware.
pub struct TestQuantumSource {
    state: u64,
}

impl TestQuantumSource {
    pub fn seeded(seed: u64) -> Self {
        Self {
            state: seed | 1, // avoid the zero fixed point
        }
    }
}

impl QuantumSource for TestQuantumSource {
    fn fill_entropy(&mut self, dest: &mut [u8]) -> Result<(), PqcError> {
        for chunk in dest.chunks_mut(8) {
            // xorshift64
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.state = x;
            let bytes = x.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}
