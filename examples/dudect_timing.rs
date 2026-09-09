//! Local dudect-style timing-analysis harness for the WP2 constant-time ML-DSA
//! signing kernel.
//!
//! Objective: provide empirical evidence that signing latency is independent of
//! the secret key. The harness follows the classic "fixed vs. random" dudect
//! methodology:
//!
//! - **Class A (fixed):** a single, hardcoded private key is reused for every
//!   measurement; only the message changes between iterations.
//! - **Class B (random):** a freshly generated (random-seed) private key is used
//!   for every measurement, so the secret material varies sample-to-sample.
//!
//! We record cycle counts for both classes and compute the Welch two-sample
//! t-statistic `|t|`. A constant-time implementation converges to `|t| < 4.5`
//! as the sample count grows — the threshold required by the review criteria.
//!
//! Run with a large stack (the kernel requires ~64 MB):
//!
//! ```text
//! RUST_MIN_STACK=67108864 cargo run --example dudect_timing --release
//! ```
//!
//! This example drives the production signing path through
//! `paraxiom_pqc::dsa_ct::sign_constant_time` — the public dispatcher that wraps
//! the vendored fork kernel, including the context-length guard and the retry
//! loop I added. Measuring this entry point gives empirical timing evidence for
//! the full production-ready path, not just the underlying kernel.

use ml_dsa::{MlDsa65, SigningKey};
use paraxiom_pqc::dsa_ct::sign_constant_time;
use std::io::Write;

/// Number of measurements per class. 200k gives high statistical confidence.
const SAMPLES: usize = 200_000;

/// Fixed 32-byte seed for Class A (hardcoded private key).
const FIXED_SEED: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// Fill `buf` with fresh OS randomness (random messages and Class B keys).
fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("RNG failure");
}

#[inline(never)]
fn rdtsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Fallback: coarse wall-clock nanoseconds. On non-x86 the t-statistic is
        // still meaningful for relative comparison, though cycle accuracy drops.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}

fn main() {
    let fixed_key: SigningKey<MlDsa65> =
        SigningKey::<MlDsa65>::from_seed(&ml_dsa::B32::from(FIXED_SEED));

    let mut class_a = Vec::with_capacity(SAMPLES);
    let mut class_b = Vec::with_capacity(SAMPLES);
    let mut msg = [0u8; 32];
    let mut key_seed = [0u8; 32];

    for i in 0..SAMPLES {
        // Class A: fixed key, random message.
        random_bytes(&mut msg);
        let start = rdtsc();
        let sig = sign_constant_time(&fixed_key, &msg, b"")
            .expect("constant-time sign (fixed key) must succeed");
        let end = rdtsc();
        std::hint::black_box(&sig);
        class_a.push(end.wrapping_sub(start));

        // Class B: random key, random message.
        random_bytes(&mut msg);
        random_bytes(&mut key_seed);
        let random_key: SigningKey<MlDsa65> =
            SigningKey::<MlDsa65>::from_seed(&ml_dsa::B32::from(key_seed));
        let start = rdtsc();
        let sig = sign_constant_time(&random_key, &msg, b"")
            .expect("constant-time sign (random key) must succeed");
        let end = rdtsc();
        std::hint::black_box(&sig);
        class_b.push(end.wrapping_sub(start));

        if (i + 1) % 10_000 == 0 {
            eprintln!("dudect: completed {} iterations...", i + 1);
            std::io::stderr().flush().ok();
        }
    }

    let t = welch_t(&class_a, &class_b);
    let mut out = String::new();
    out.push_str(&format!("dudect: samples per class = {}\n", SAMPLES));
    out.push_str(&format!(
        "dudect: mean cycles  class A (fixed key) = {:.1}\n",
        mean(&class_a)
    ));
    out.push_str(&format!(
        "dudect: mean cycles  class B (random key) = {:.1}\n",
        mean(&class_b)
    ));
    out.push_str(&format!("dudect: |t| = {:.4}\n", t.abs()));
    out.push_str(&format!(
        "dudect: status = {}\n",
        if t.abs() < 4.5 {
            "PASS (|t| < 4.5): no timing signal detected"
        } else {
            "FAIL (|t| >= 4.5): timing signal present"
        }
    ));
    print!("{}", out);
    std::io::stdout().flush().expect("flush stdout");
}

fn mean(xs: &[u64]) -> f64 {
    xs.iter().map(|v| *v as f64).sum::<f64>() / xs.len() as f64
}

fn variance(xs: &[u64]) -> f64 {
    let m = mean(xs);
    xs.iter().map(|v| (*v as f64 - m).powi(2)).sum::<f64>() / (xs.len() as f64 - 1.0)
}

/// Welch's two-sample t-test (unequal variances), returning the t-statistic.
fn welch_t(a: &[u64], b: &[u64]) -> f64 {
    let na = a.len() as f64;
    let nb = b.len() as f64;
    let ma = mean(a);
    let mb = mean(b);
    let va = variance(a);
    let vb = variance(b);
    let se = (va / na + vb / nb).sqrt();
    (ma - mb) / se
}
