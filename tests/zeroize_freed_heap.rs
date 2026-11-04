//! Secret bytes must not be left in heap memory that the ML-KEM and Falcon calls free on their way.
//!
//! `tests/zeroize.rs` checks a key's own heap allocations when the key is dropped. It does not see
//! a temporary copy that a call makes and frees before it returns, such as a cloned decryption key
//! inside `decapsulate`. This test binary installs a global allocator that, while one thread is
//! watched, copies every buffer that thread frees into a fixed arena, just before the buffer goes
//! back to the system allocator. Each test runs one API call under watch and then searches the
//! arena for the secrets:
//! - ML-KEM: the seed halves d and z, 32-byte windows of the secret vector s_hat (as ml-kem keeps
//!   it in memory, and as encoded), and for decapsulation the message m and the shared secret;
//! - Falcon: 24-byte windows of the encoded private key.
//!
//! A positive control checks that a secret freed without being cleared is found.
//!
//! Limits: only frees made by the watched thread are seen. Memory that is never freed, the stack
//! and registers are not checked. The needles are windows, so a secret kept only in pieces
//! shorter than a window, or in another encoding, is not found.

use paraxiom_pqc::kem::{self, Ciphertext, DecapsulationKey, KemAlgorithm};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, UnsafeCell};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::Mutex;

struct Snapshot;
const ARENA: usize = 16 << 20;
struct Arena(UnsafeCell<[u8; ARENA]>);
// SAFETY: the arena is written only through offsets handed out by an atomic counter, so no two
// writers share bytes, and it is read only by `watch` after the watched call has returned.
unsafe impl Sync for Arena {}
static ARENA_BUF: Arena = Arena(UnsafeCell::new([0; ARENA]));
static ARENA_LEN: AtomicUsize = AtomicUsize::new(0);
static ARENA_OVERFLOW: AtomicBool = AtomicBool::new(false);
static FREES: AtomicUsize = AtomicUsize::new(0);
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
thread_local! { static WATCHED: Cell<bool> = const { Cell::new(false) }; }

unsafe impl GlobalAlloc for Snapshot {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if !p.is_null() && WATCHED.try_with(Cell::get).unwrap_or(false) {
            FREES.fetch_add(1, SeqCst);
            let n = l.size();
            let off = ARENA_LEN.fetch_add(n, SeqCst);
            if off + n <= ARENA {
                unsafe {
                    let dst = (ARENA_BUF.0.get() as *mut u8).add(off);
                    std::ptr::copy_nonoverlapping(p, dst, n);
                }
            } else {
                ARENA_OVERFLOW.store(true, SeqCst);
            }
        }
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static ALLOCATOR: Snapshot = Snapshot;

/// What the watched thread freed during one call: how many buffers, and their bytes end to end.
struct Freed {
    frees: usize,
    bytes: Vec<u8>,
}

/// Runs `f` with this thread watched and returns its result and what it freed.
fn watch<T>(f: impl FnOnce() -> T) -> (T, Freed) {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
    ARENA_LEN.store(0, SeqCst);
    ARENA_OVERFLOW.store(false, SeqCst);
    FREES.store(0, SeqCst);
    WATCHED.with(|w| w.set(true));
    let v = f();
    WATCHED.with(|w| w.set(false));
    assert!(
        !ARENA_OVERFLOW.load(SeqCst),
        "the arena is too small for what the call freed"
    );
    let len = ARENA_LEN.load(SeqCst);
    let bytes = unsafe { (&*ARENA_BUF.0.get())[..len].to_vec() };
    (
        v,
        Freed {
            frees: FREES.load(SeqCst),
            bytes,
        },
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The names of the needles found in the freed bytes.
fn found(freed: &Freed, needles: &[(String, Vec<u8>)]) -> Vec<String> {
    needles
        .iter()
        .filter(|(_, n)| contains(&freed.bytes, n))
        .map(|(name, _)| name.clone())
        .collect()
}

/// One line for each call that left secrets behind, with the windows of one secret counted
/// together, such as "MlKem768 keypair: d, s_hat in memory (24 windows)".
fn leaks(report: &[(String, usize, Vec<String>)]) -> Vec<String> {
    report
        .iter()
        .filter(|(_, _, hits)| !hits.is_empty())
        .map(|(call, _, hits)| {
            let mut groups: Vec<(String, usize)> = Vec::new();
            for hit in hits {
                let name = hit.split(" [").next().unwrap_or(hit).to_string();
                match groups.iter_mut().find(|(n, _)| *n == name) {
                    Some((_, count)) => *count += 1,
                    None => groups.push((name, 1)),
                }
            }
            let parts: Vec<String> = groups
                .into_iter()
                .map(|(n, c)| {
                    if c == 1 {
                        n
                    } else {
                        format!("{n} ({c} windows)")
                    }
                })
                .collect();
            format!("{call}: {}", parts.join(", "))
        })
        .collect()
}

/// s_hat as ml-kem 0.3.3 keeps it in memory: u16 coefficients, native endian.
fn s_hat_in_memory(expanded_dk: &[u8], k: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for t in expanded_dk[..384 * k].chunks(3) {
        let a = u16::from(t[0]) | (u16::from(t[1] & 0x0f) << 8);
        let b = u16::from(t[1] >> 4) | (u16::from(t[2]) << 4);
        out.extend_from_slice(&a.to_ne_bytes());
        out.extend_from_slice(&b.to_ne_bytes());
    }
    out
}

/// Secret needles for a seed: d, z, and 32-byte windows of s_hat in memory form and 24-byte windows
/// of its encoding.
macro_rules! kem_needles {
    ($P:ty, $seed:expr, $k:expr) => {{
        #[allow(deprecated)]
        use ml_kem::ExpandedKeyEncoding;
        use ml_kem::KeyInit;
        let seed: &[u8] = $seed;
        let k: usize = $k;
        let s = ml_kem::Seed::try_from(seed).unwrap();
        let key = ml_kem::DecapsulationKey::<$P>::new(&s);
        #[allow(deprecated)]
        let expanded = key.to_expanded_bytes();
        let mem = s_hat_in_memory(&expanded, k);
        let mut v = vec![
            ("d".to_string(), seed[..32].to_vec()),
            ("z".to_string(), seed[32..].to_vec()),
        ];
        for i in 0..(mem.len() / 64) {
            v.push((
                format!("s_hat in memory [{}..]", i * 64),
                mem[i * 64..i * 64 + 32].to_vec(),
            ));
        }
        for i in 0..((384 * k) / 48) {
            v.push((
                format!("s_hat encoded [{}..]", i * 48),
                expanded[i * 48..i * 48 + 24].to_vec(),
            ));
        }
        v
    }};
}

fn rank(alg: KemAlgorithm) -> usize {
    match alg {
        KemAlgorithm::MlKem512 => 2,
        KemAlgorithm::MlKem768 => 3,
        KemAlgorithm::MlKem1024 => 4,
    }
}

fn needles_for(alg: KemAlgorithm, seed: &[u8]) -> Vec<(String, Vec<u8>)> {
    let k = rank(alg);
    match alg {
        KemAlgorithm::MlKem512 => kem_needles!(ml_kem::MlKem512, seed, k),
        KemAlgorithm::MlKem768 => kem_needles!(ml_kem::MlKem768, seed, k),
        KemAlgorithm::MlKem1024 => kem_needles!(ml_kem::MlKem1024, seed, k),
    }
}

/// The encapsulation key for a seed, made outside any watch.
fn encapsulation_key_for(alg: KemAlgorithm, seed: &[u8]) -> Vec<u8> {
    use ml_kem::{KeyExport, KeyInit};
    macro_rules! go {
        ($P:ty) => {{
            let s = ml_kem::Seed::try_from(seed).unwrap();
            ml_kem::DecapsulationKey::<$P>::new(&s)
                .encapsulation_key()
                .to_bytes()
                .to_vec()
        }};
    }
    match alg {
        KemAlgorithm::MlKem512 => go!(ml_kem::MlKem512),
        KemAlgorithm::MlKem768 => go!(ml_kem::MlKem768),
        KemAlgorithm::MlKem1024 => go!(ml_kem::MlKem1024),
    }
}

/// Encapsulates with a known m, through ml-kem's own deterministic encapsulation, outside any
/// watch. Returns the ciphertext and the shared secret.
fn encapsulate_known_m(alg: KemAlgorithm, ek: &[u8], m: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use ml_kem::TryKeyInit;
    let m = ml_kem::B32::try_from(&m[..]).unwrap();
    macro_rules! go {
        ($P:ty) => {{
            let ek_t = ml_kem::EncapsulationKey::<$P>::new_from_slice(ek).unwrap();
            let (c, k) = ek_t.encapsulate_deterministic(&m);
            (c.as_slice().to_vec(), k.as_slice().to_vec())
        }};
    }
    match alg {
        KemAlgorithm::MlKem512 => go!(ml_kem::MlKem512),
        KemAlgorithm::MlKem768 => go!(ml_kem::MlKem768),
        KemAlgorithm::MlKem1024 => go!(ml_kem::MlKem1024),
    }
}

const KEM_ALGORITHMS: [KemAlgorithm; 3] = [
    KemAlgorithm::MlKem512,
    KemAlgorithm::MlKem768,
    KemAlgorithm::MlKem1024,
];

#[test]
fn control_a_secret_freed_without_clearing_is_found() {
    let secret = [0x5Au8; 32];
    let (_, freed) = watch(|| {
        // `black_box` keeps an optimized build from removing an allocation nothing reads.
        let v = std::hint::black_box(secret.to_vec());
        drop(v);
    });
    assert!(freed.frees >= 1, "the control freed nothing under watch");
    assert_eq!(
        found(&freed, &[("secret".into(), secret.to_vec())]),
        vec!["secret".to_string()]
    );
}

#[test]
fn ml_kem_calls_leave_no_secret_in_freed_heap() {
    let mut report = Vec::new();
    for alg in KEM_ALGORITHMS {
        // keypair: the needles come from the seed it returns.
        let (kp, freed) = watch(|| kem::keypair(alg).unwrap());
        let needles = needles_for(alg, &kp.dk.bytes);
        report.push((
            format!("{alg:?} keypair"),
            freed.frees,
            found(&freed, &needles),
        ));

        // decapsulate a valid ciphertext made with a known m.
        let seed: Vec<u8> = (0u8..64)
            .map(|i| i.wrapping_mul(53).wrapping_add(7))
            .collect();
        let dk = DecapsulationKey {
            algorithm: alg,
            bytes: seed.clone(),
        };
        let ek = encapsulation_key_for(alg, &seed);
        let m = [0xC3u8; 32];
        let (c, shared) = encapsulate_known_m(alg, &ek, &m);
        let mut needles = needles_for(alg, &seed);
        needles.push(("m".into(), m.to_vec()));
        needles.push(("shared secret".into(), shared.clone()));
        let ct = Ciphertext {
            algorithm: alg,
            bytes: c.clone(),
        };
        let (ss, freed) = watch(|| kem::decapsulate(&dk, &ct).unwrap());
        assert_eq!(
            ss.bytes, shared,
            "{alg:?}: decapsulation gave another secret"
        );
        report.push((
            format!("{alg:?} decapsulate, valid ciphertext"),
            freed.frees,
            found(&freed, &needles),
        ));

        // decapsulate a modified ciphertext (implicit rejection).
        let mut bad = c.clone();
        bad[0] ^= 1;
        let ct_bad = Ciphertext {
            algorithm: alg,
            bytes: bad,
        };
        let (rejected, freed) = watch(|| kem::decapsulate(&dk, &ct_bad).unwrap());
        let mut needles_bad = needles.clone();
        needles_bad.push(("rejection secret".into(), rejected.bytes.clone()));
        report.push((
            format!("{alg:?} decapsulate, modified ciphertext"),
            freed.frees,
            found(&freed, &needles_bad),
        ));

        // encapsulate: the shared secret must not be left in freed memory.
        let ek_w = kem::EncapsulationKey {
            algorithm: alg,
            bytes: ek.clone(),
        };
        let ((_, ss), freed) = watch(|| kem::encapsulate(&ek_w).unwrap());
        report.push((
            format!("{alg:?} encapsulate"),
            freed.frees,
            found(&freed, &[("shared secret".into(), ss.bytes.clone())]),
        ));
    }
    for (call, frees, hits) in &report {
        println!("{call}: {frees} buffers freed, secrets found: {hits:?}");
    }
    let leaks = leaks(&report);
    assert!(
        leaks.is_empty(),
        "secret bytes left in freed heap memory:\n{}",
        leaks.join("\n")
    );
}

#[cfg(feature = "sign")]
#[test]
fn falcon_calls_leave_no_private_key_bytes_in_freed_heap() {
    use paraxiom_pqc::sign::{self, SignAlgorithm};
    if !sign::FALCON_SIGNING_AVAILABLE {
        return;
    }
    let mut report = Vec::new();
    for alg in [SignAlgorithm::Falcon512, SignAlgorithm::Falcon1024] {
        let (kp, freed_keygen) = watch(|| sign::keypair(alg).unwrap());
        let sk = kp.sk.bytes.clone();
        // 24-byte windows of the encoded private key, after its header byte.
        let mut needles = Vec::new();
        let mut i = 1;
        while i + 24 <= sk.len() {
            needles.push((format!("private key [{i}..]"), sk[i..i + 24].to_vec()));
            i += 96;
        }
        assert!(!needles.is_empty());
        report.push((
            format!("{alg:?} keypair"),
            freed_keygen.frees,
            found(&freed_keygen, &needles),
        ));
        let (sig, freed_sign) = watch(|| sign::sign(&kp.sk, b"freed heap").unwrap());
        assert!(sign::verify(&kp.vk, b"freed heap", &sig).unwrap());
        report.push((
            format!("{alg:?} sign"),
            freed_sign.frees,
            found(&freed_sign, &needles),
        ));
    }
    for (call, frees, hits) in &report {
        println!("{call}: {frees} buffers freed, private key windows found: {hits:?}");
    }
    let leaks = leaks(&report);
    assert!(
        leaks.is_empty(),
        "private key bytes left in freed heap memory:\n{}",
        leaks.join("\n")
    );
}
