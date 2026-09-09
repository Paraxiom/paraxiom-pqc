//! Diagnostic dudect harness that isolates individual ML-DSA pipeline components.
//!
//! This harness measures timing differences between Class A (fixed key) and
//! Class B (random key) for each individual component to identify which
//! function is causing the timing side-channel leak.

use ml_dsa::{MlDsa65, SigningKey};
use std::io::Write;

/// Number of measurements per class. Reduced for faster iteration during diagnosis.
const SAMPLES: usize = 500;

/// Fixed 32-byte seed for Class A (hardcoded private key).
const FIXED_SEED: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

/// Fill `buf` with fresh OS randomness.
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
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
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

/// Print t-statistic results for a named component.
fn report(name: &str, class_a: &[u64], class_b: &[u64]) {
    let t = welch_t(class_a, class_b);
    let status = if t.abs() < 4.5 {
        "PASS (|t| < 4.5): no timing signal detected"
    } else {
        "FAIL (|t| >= 4.5): timing signal present"
    };
    println!(
        "  {:<30} |t| = {:.4}  mean_A = {:.1}  mean_B = {:.1}  {}",
        name,
        t.abs(),
        mean(class_a),
        mean(class_b),
        status
    );
}

fn main() {
    let fixed_key: SigningKey<MlDsa65> =
        SigningKey::<MlDsa65>::from_seed(&ml_dsa::B32::from(FIXED_SEED));

    let mut msg = [0u8; 32];
    let mut key_seed = [0u8; 32];

    // Vectors for each component
    let mut full_sign_a = Vec::with_capacity(SAMPLES);
    let mut full_sign_b = Vec::with_capacity(SAMPLES);

    // We'll also measure key expansion separately
    let mut key_expansion_a = Vec::with_capacity(SAMPLES);
    let mut key_expansion_b = Vec::with_capacity(SAMPLES);

    // Benchmark components using the bench feature
    let mut sample_in_ball_a = Vec::with_capacity(SAMPLES);
    let mut sample_in_ball_b = Vec::with_capacity(SAMPLES);
    let mut rej_bounded_poly_a = Vec::with_capacity(SAMPLES);
    let mut rej_bounded_poly_b = Vec::with_capacity(SAMPLES);
    let mut rej_ntt_poly_a = Vec::with_capacity(SAMPLES);
    let mut rej_ntt_poly_b = Vec::with_capacity(SAMPLES);

    println!("=== ML-DSA Component Timing Audit ===");
    println!("Samples per class: {}", SAMPLES);

    for i in 0..SAMPLES {
        // Class A: fixed key, random message.
        random_bytes(&mut msg);

        // Measure full sign
        let start = rdtsc();
        let _sig = paraxiom_pqc::dsa_ct::sign_constant_time(&fixed_key, &msg, b"")
            .expect("constant-time sign (fixed key) must succeed");
        let end = rdtsc();
        std::hint::black_box(&_sig);
        full_sign_a.push(end.wrapping_sub(start));

        // Class B: random key, random message.
        random_bytes(&mut msg);
        random_bytes(&mut key_seed);

        // Measure key expansion with fixed key
        let start = rdtsc();
        let _ = fixed_key.rho;
        let end = rdtsc();
        std::hint::black_box(&fixed_key);
        key_expansion_a.push(end.wrapping_sub(start));

        // Measure key expansion with random key
        let start = rdtsc();
        let random_key: SigningKey<MlDsa65> =
            SigningKey::<MlDsa65>::from_seed(&ml_dsa::B32::from(key_seed));
        let end = rdtsc();
        std::hint::black_box(&random_key);
        key_expansion_b.push(end.wrapping_sub(start));

        // Measure full sign with random key
        let start = rdtsc();
        let _sig = paraxiom_pqc::dsa_ct::sign_constant_time(&random_key, &msg, b"")
            .expect("constant-time sign (random key) must succeed");
        let end = rdtsc();
        std::hint::black_box(&_sig);
        full_sign_b.push(end.wrapping_sub(start));

        // Measure sample_in_ball with fixed rho (from fixed key)
        let start = rdtsc();
        let _c = ml_dsa::bench::sample_in_ball_bench(&fixed_key.rho, 60); // MlDsa65 TAU = 60
        let end = rdtsc();
        std::hint::black_box(&_c);
        sample_in_ball_a.push(end.wrapping_sub(start));

        // Measure sample_in_ball with random rho
        let start = rdtsc();
        let _c = ml_dsa::bench::sample_in_ball_bench(&key_seed, 60);
        let end = rdtsc();
        std::hint::black_box(&_c);
        sample_in_ball_b.push(end.wrapping_sub(start));

// Measure rej_bounded_poly with fixed rho
        let start = rdtsc();
        let _p = ml_dsa::bench::rej_bounded_poly_bench(&fixed_key.rho, ml_dsa::param_types::Eta::Two, 0);
        let end = rdtsc();
        std::hint::black_box(&_p);
        rej_bounded_poly_a.push(end.wrapping_sub(start));

        // Measure rej_bounded_poly with random rho
        let start = rdtsc();
        let _p = ml_dsa::bench::rej_bounded_poly_bench(&key_seed, ml_dsa::param_types::Eta::Two, 0);
        let end = rdtsc();
        std::hint::black_box(&_p);
        rej_bounded_poly_b.push(end.wrapping_sub(start));

        // Measure rej_ntt_poly with fixed rho
        let start = rdtsc();
        let _p = ml_dsa::bench::rej_ntt_poly_bench(&fixed_key.rho, 0, 0);
        let end = rdtsc();
        std::hint::black_box(&_p);
        rej_ntt_poly_a.push(end.wrapping_sub(start));

        // Measure rej_ntt_poly with random rho
        let start = rdtsc();
        let _p = ml_dsa::bench::rej_ntt_poly_bench(&key_seed, 0, 0);
        let end = rdtsc();
        std::hint::black_box(&_p);
        rej_ntt_poly_b.push(end.wrapping_sub(start));

        if (i + 1) % 10_000 == 0 {
            eprintln!("dudect: completed {} iterations...", i + 1);
            std::io::stderr().flush().ok();
        }
    }

    println!("\n=== Component Timing Results ===");
    report("Full sign_constant_time", &full_sign_a, &full_sign_b);
    report("Key expansion", &key_expansion_a, &key_expansion_b);
    report("sample_in_ball", &sample_in_ball_a, &sample_in_ball_b);
    report("rej_bounded_poly", &rej_bounded_poly_a, &rej_bounded_poly_b);
    report("rej_ntt_poly", &rej_ntt_poly_a, &rej_ntt_poly_b);

    println!("\n=== Analysis ===");
    println!("If any component shows |t| >= 4.5, it indicates a timing side-channel");
    println!("leak specific to that component. The full signing result shows whether");
    println!("the overall constant-time implementation passes the dudect threshold.");

    println!("\n=== Next Steps ===");
    println!("If a timing leak is detected in a specific component, consider:");
    println!("1. Reviewing that component for data-dependent branches or memory access");
    println!("2. Ensuring constant-time implementations for all arithmetic operations");
    println!("3. Re-running the audit after fixes to confirm |t| < 4.5");
}