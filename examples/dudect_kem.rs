//! dudect ML-KEM-768 decapsulation timing test: VALID vs INVALID ciphertext.
//!
//! ML-KEM's Fujisaki-Okamoto transform *implicitly rejects* invalid ciphertexts
//! (returns a pseudorandom secret) instead of erroring. A constant-time decap must
//! take the **same time** whether the ciphertext is valid or tampered — otherwise
//! decap timing is a validity oracle (a known Kyber/ML-KEM side-channel class).
//! |t| > 4.5 ⇒ measurable validity-dependent timing.
//!
//!   cargo run --release --example dudect_kem [n]
use paraxiom_pqc::kem::{self, Ciphertext, KemAlgorithm};
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
    let d = (v1 / n1 + v2 / n2).sqrt();
    if d == 0.0 {
        0.0
    } else {
        (m1 - m2) / d
    }
}
fn crop(v: &[f64], pct: f64) -> Vec<f64> {
    if pct >= 100.0 {
        return v.to_vec();
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = (((s.len() as f64) * pct / 100.0) as usize).saturating_sub(1);
    let cut = s[i];
    v.iter().cloned().filter(|x| *x <= cut).collect()
}
fn max_t(a: &[f64], b: &[f64]) -> f64 {
    let mut best = 0.0f64;
    for p in [100.0, 99.0, 95.0, 90.0] {
        let t = welch_t(&crop(a, p), &crop(b, p)).abs();
        if t > best {
            best = t;
        }
    }
    best
}

fn main() {
    let alg = KemAlgorithm::MlKem768;
    let kp = kem::keypair(alg).unwrap();
    let pool = 512usize;
    let valid: Vec<Ciphertext> = (0..pool)
        .map(|_| kem::encapsulate(&kp.ek).unwrap().0)
        .collect();
    let invalid: Vec<Ciphertext> = valid
        .iter()
        .map(|c| {
            let mut b = c.bytes.clone();
            let m = b.len() / 2;
            b[m] ^= 1; // flip a middle byte → invalid ciphertext
            Ciphertext {
                algorithm: c.algorithm,
                bytes: b,
            }
        })
        .collect();
    for c in valid.iter().take(50) {
        let _ = kem::decapsulate(&kp.dk, c);
    }
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let mut tv = Vec::with_capacity(n);
    let mut ti = Vec::with_capacity(n);
    let mut seed = 0x9e3779b97f4a7c15u64;
    for _ in 0..n {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let idx = (seed >> 1) as usize % pool;
        if seed & 1 == 0 {
            let t = Instant::now();
            let _ = kem::decapsulate(&kp.dk, &valid[idx]).unwrap();
            tv.push(t.elapsed().as_nanos() as f64);
        } else {
            let t = Instant::now();
            let _ = kem::decapsulate(&kp.dk, &invalid[idx]).unwrap();
            ti.push(t.elapsed().as_nanos() as f64);
        }
    }
    let t = max_t(&tv, &ti);
    let mv = tv.iter().sum::<f64>() / tv.len() as f64;
    let mi = ti.iter().sum::<f64>() / ti.len() as f64;
    println!("# dudect ML-KEM-768 decapsulation — VALID vs INVALID ciphertext");
    println!(
        "# arch={}  |t|>4.5 => validity timing oracle",
        std::env::consts::ARCH
    );
    println!(
        "ML-KEM-768 decap | n={}/{} | valid~{:.0}ns invalid~{:.0}ns | |t|={:.2} | {}",
        tv.len(),
        ti.len(),
        mv,
        mi,
        t,
        if t > 4.5 {
            "LEAK — validity timing oracle"
        } else {
            "constant-time (no validity leak)"
        }
    );
}
