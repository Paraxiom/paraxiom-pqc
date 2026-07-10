//! dudect-style timing-leakage test for paraxiom-pqc signing.
//!
//! Method (Reparaz et al., "dude, is my code constant time?"): for each scheme,
//! interleave two measurement classes — FIXED secret key vs a pool of RANDOM keys
//! — sign a fixed message, time only the sign() call, then run Welch's t-test on
//! the two timing populations with upper-percentile cropping (lower measurements
//! are cleaner). |t| > 4.5 ⇒ statistically significant key-dependent timing, i.e.
//! NOT constant-time on this CPU.
//!
//! This is the TIMING side-channel only. Power/EM analysis needs a lab (CSIT).
//! SLH-DSA (hash-based) is the constant-time control; Falcon-512 (floating-point
//! Gaussian sampler) is the expected hot spot.
//!
//!   cargo run --release --example dudect_timing [scale]

use paraxiom_pqc::sign::{self, SignAlgorithm, SignKeypair};
use std::time::Instant;

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let (n1, n2) = (a.len() as f64, b.len() as f64);
    if n1 < 2.0 || n2 < 2.0 {
        return 0.0;
    }
    let m1 = a.iter().sum::<f64>() / n1;
    let m2 = b.iter().sum::<f64>() / n2;
    let v1 = a.iter().map(|x| (x - m1).powi(2)).sum::<f64>() / (n1 - 1.0);
    let v2 = b.iter().map(|x| (x - m2).powi(2)).sum::<f64>() / (n2 - 1.0);
    let denom = (v1 / n1 + v2 / n2).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (m1 - m2) / denom
    }
}

fn crop(v: &[f64], pct: f64) -> Vec<f64> {
    if pct >= 100.0 {
        return v.to_vec();
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = (((s.len() as f64) * pct / 100.0) as usize).saturating_sub(1);
    let cut = s[idx];
    v.iter().cloned().filter(|x| *x <= cut).collect()
}

/// dudect statistic: max |t| over several upper-crop percentiles.
fn max_t(fix: &[f64], rnd: &[f64]) -> f64 {
    let mut best = 0.0f64;
    for pct in [100.0, 99.0, 95.0, 90.0] {
        let t = welch_t(&crop(fix, pct), &crop(rnd, pct)).abs();
        if t > best {
            best = t;
        }
    }
    best
}

fn measure(alg: SignAlgorithm, label: &str, n: usize, pool: usize, rnd: bool) {
    let msg = [0x42u8; 32];
    let do_sign = |k: &paraxiom_pqc::sign::SigningKey| {
        if rnd {
            sign::sign_randomized(k, &msg)
        } else {
            sign::sign(k, &msg)
        }
    };
    let fixed: SignKeypair = sign::keypair(alg).unwrap();
    let keys: Vec<SignKeypair> = (0..pool).map(|_| sign::keypair(alg).unwrap()).collect();
    for _ in 0..50 {
        let _ = do_sign(&fixed.sk);
    } // warm up
    let mut tf = Vec::with_capacity(n);
    let mut tr = Vec::with_capacity(n);
    let mut seed = 0x9e3779b97f4a7c15u64;
    for _ in 0..n {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17; // xorshift64
        if seed & 1 == 0 {
            let t = Instant::now();
            let _ = do_sign(&fixed.sk).unwrap();
            tf.push(t.elapsed().as_nanos() as f64);
        } else {
            let k = &keys[(seed >> 1) as usize % keys.len()];
            let t = Instant::now();
            let _ = do_sign(&k.sk).unwrap();
            tr.push(t.elapsed().as_nanos() as f64);
        }
    }
    let t = max_t(&tf, &tr);
    let mf = tf.iter().sum::<f64>() / tf.len().max(1) as f64;
    let mr = tr.iter().sum::<f64>() / tr.len().max(1) as f64;
    let verdict = if t > 4.5 {
        "LEAK — key-dependent timing"
    } else {
        "no timing leak detected"
    };
    println!(
        "{:<24} | n={:>6}/{:<6} | fix~{:>8.0}ns rnd~{:>8.0}ns | |t|={:>8.2} | {}",
        label,
        tf.len(),
        tr.len(),
        mf,
        mr,
        t,
        verdict
    );
}

fn main() {
    let scale: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    println!("# dudect timing-leakage — paraxiom-pqc sign (FIXED vs RANDOM key)");
    println!(
        "# arch={}  scale={}  |t|>4.5 => measurable key-dependent timing (not constant-time)",
        std::env::consts::ARCH,
        scale
    );
    println!("{}", "-".repeat(96));
    // (alg, label, base_n, pool) — n tuned to keep slow schemes bounded
    measure(
        SignAlgorithm::SlhDsaShake128f,
        "SLH-DSA-128f (control)",
        400 * scale,
        64,
        false,
    );
    measure(
        SignAlgorithm::Falcon512,
        "Falcon-512",
        20_000 * scale,
        256,
        false,
    );
    measure(
        SignAlgorithm::MlDsa44,
        "ML-DSA-44 DETERMINISTIC",
        20_000 * scale,
        256,
        false,
    );
    measure(
        SignAlgorithm::MlDsa44,
        "ML-DSA-44 RANDOMIZED",
        20_000 * scale,
        256,
        true,
    );
}
