//! The secret types must clear their heap buffers before the memory goes back to the allocator.
//!
//! This test binary installs a global allocator that wraps the system allocator. When the one
//! watched buffer is freed, it looks at the bytes first and records a verdict. Each test
//! watches the buffer of one secret value, drops the value, and reads the verdict.
//!
//! Two verdicts:
//! - `cleared_when_freed`: every byte of the allocation is zero. For this crate's own secret
//!   types (`DecapsulationKey`, `SharedSecret`, `SigningKey`), whose only heap buffer is the
//!   secret itself, including spare capacity.
//! - `secrets_gone_when_freed`: none of the given secret byte strings is left anywhere in the
//!   allocation. For key structs that keep public parts next to their secrets (the backend keys,
//!   boxed so that they live on the heap, and `QrngRng`); the strings are checked to be present
//!   before the drop, so the test cannot pass vacuously.
//!
//! Controls: a plain `Vec` must be reported as not cleared, and a boxed array holding a secret
//! string must be reported as still holding it.

use paraxiom_pqc::kem::{self, Ciphertext, DecapsulationKey, KemAlgorithm, SharedSecret};
use proptest::prelude::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

struct WatchingAllocator;

/// Address of the watched buffer, 0 when nothing is watched.
static WATCHED: AtomicUsize = AtomicUsize::new(0);
/// 0: not freed yet, 1: freed and passed the check, 2: freed and failed it.
static VERDICT: AtomicU8 = AtomicU8::new(0);
/// Tests run in parallel; one watch at a time.
static ONE_WATCH: Mutex<()> = Mutex::new(());

/// Secret strings to look for, for `secrets_gone_when_freed`. Fixed storage: the allocator must
/// not allocate while it inspects a buffer. Written only while `ONE_WATCH` is held and nothing
/// is watched, read only by the thread that holds it.
const MAX_NEEDLES: usize = 8;
const MAX_NEEDLE_LEN: usize = 64;
struct Needles(UnsafeCell<[(usize, [u8; MAX_NEEDLE_LEN]); MAX_NEEDLES]>);
// SAFETY: access is serialised by ONE_WATCH (see above).
unsafe impl Sync for Needles {}
static NEEDLES: Needles = Needles(UnsafeCell::new([(0, [0; MAX_NEEDLE_LEN]); MAX_NEEDLES]));
/// Number of needles in use; 0 means "check that every byte is zero".
static NEEDLE_COUNT: AtomicUsize = AtomicUsize::new(0);

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The check run on a buffer: all zero, or none of the needles present.
fn passes(bytes: &[u8]) -> bool {
    let n = NEEDLE_COUNT.load(Ordering::SeqCst);
    if n == 0 {
        return bytes.iter().all(|b| *b == 0);
    }
    // SAFETY: only read by the watching thread while the needles are set (see NEEDLES).
    let needles = unsafe { &*NEEDLES.0.get() };
    needles[..n]
        .iter()
        .all(|(len, buf)| !contains(bytes, &buf[..*len]))
}

unsafe impl GlobalAlloc for WatchingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !ptr.is_null() && ptr as usize == WATCHED.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is still a live allocation of `layout.size()` bytes; it is only
            // released by the call below.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            VERDICT.store(if passes(bytes) { 1 } else { 2 }, Ordering::SeqCst);
            WATCHED.store(0, Ordering::SeqCst);
        }
        // SAFETY: forwarded unchanged to the system allocator that produced `ptr`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WatchingAllocator = WatchingAllocator;

fn watch<T>(value: T, buffer: *const u8, needles: &[&[u8]]) -> bool {
    let _one = ONE_WATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(needles.len() <= MAX_NEEDLES);
    // SAFETY: ONE_WATCH is held and nothing is watched, so the allocator does not read NEEDLES.
    let store = unsafe { &mut *NEEDLES.0.get() };
    for (slot, n) in store.iter_mut().zip(needles) {
        assert!(!n.is_empty() && n.len() <= MAX_NEEDLE_LEN);
        slot.0 = n.len();
        slot.1[..n.len()].copy_from_slice(n);
    }
    NEEDLE_COUNT.store(needles.len(), Ordering::SeqCst);
    VERDICT.store(0, Ordering::SeqCst);
    WATCHED.store(buffer as usize, Ordering::SeqCst);
    drop(value);
    WATCHED.store(0, Ordering::SeqCst);
    NEEDLE_COUNT.store(0, Ordering::SeqCst);
    match VERDICT.load(Ordering::SeqCst) {
        1 => true,
        2 => false,
        _ => panic!("dropping the value did not free the watched buffer"),
    }
}

/// Drops `value` and reports whether the heap buffer at `buffer` was all zero when freed.
fn cleared_when_freed<T>(value: T, buffer: *const u8) -> bool {
    watch(value, buffer, &[])
}

/// Drops the boxed `value` and reports whether none of `secrets` was left in its allocation.
/// Panics if a secret is not in the allocation to begin with.
fn secrets_gone_when_freed<T>(value: Box<T>, secrets: &[&[u8]]) -> bool {
    let ptr = &*value as *const T as *const u8;
    // SAFETY: reads the live allocation of the box, `size_of::<T>()` bytes.
    let live = unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<T>()) };
    for s in secrets {
        assert!(
            contains(live, s),
            "a secret is not in the value before the drop"
        );
    }
    watch(value, ptr, secrets)
}

const KEM_ALGS: [KemAlgorithm; 3] = [
    KemAlgorithm::MlKem512,
    KemAlgorithm::MlKem768,
    KemAlgorithm::MlKem1024,
];

// ── Controls ─────────────────────────────────────────────────────────────────

#[test]
fn control_a_plain_vec_is_not_cleared() {
    let v = vec![0xA5u8; 64];
    let p = v.as_ptr();
    assert!(
        !cleared_when_freed(v, p),
        "the harness must see data left in a plain Vec"
    );
}

#[test]
fn control_a_secret_left_in_a_box_is_found() {
    let mut a = Box::new([0x11u8; 256]);
    a[100..132].copy_from_slice(&[0x5Au8; 32]);
    assert!(
        !secrets_gone_when_freed(a, &[&[0x5Au8; 32]]),
        "the harness must find a secret left in freed memory"
    );
}

// ── This crate's secret types ────────────────────────────────────────────────

#[test]
fn decapsulation_key_is_cleared_on_drop() {
    for alg in KEM_ALGS {
        let dk = kem::keypair(alg).unwrap().dk;
        assert!(dk.bytes.iter().any(|b| *b != 0));
        let p = dk.bytes.as_ptr();
        assert!(
            cleared_when_freed(dk, p),
            "{alg:?} decapsulation key left data on the heap"
        );
    }
}

#[test]
fn shared_secrets_are_cleared_on_drop() {
    let kp = kem::keypair(KemAlgorithm::MlKem768).unwrap();
    let (ct, ss_sender) = kem::encapsulate(&kp.ek).unwrap();
    let ss_receiver = kem::decapsulate(&kp.dk, &ct).unwrap();
    assert_eq!(ss_sender.bytes, ss_receiver.bytes);

    let p = ss_sender.bytes.as_ptr();
    assert!(
        cleared_when_freed(ss_sender, p),
        "encapsulated secret left data on the heap"
    );
    let p = ss_receiver.bytes.as_ptr();
    assert!(
        cleared_when_freed(ss_receiver, p),
        "decapsulated secret left data on the heap"
    );
}

/// Every parameter set, and all three ways a shared secret is made: encapsulation,
/// decapsulation of a valid ciphertext, and implicit rejection of a modified one.
#[test]
fn shared_secrets_of_every_kind_are_cleared_on_drop() {
    for alg in KEM_ALGS {
        let kp = kem::keypair(alg).unwrap();
        let (ct, sent) = kem::encapsulate(&kp.ek).unwrap();
        let received = kem::decapsulate(&kp.dk, &ct).unwrap();
        let mut bad = ct.bytes.clone();
        bad[0] ^= 1;
        let rejected = kem::decapsulate(
            &kp.dk,
            &Ciphertext {
                algorithm: alg,
                bytes: bad,
            },
        )
        .unwrap();
        assert_ne!(rejected.bytes, received.bytes);
        for (what, ss) in [
            ("encapsulated", sent),
            ("decapsulated", received),
            ("implicit rejection", rejected),
        ] {
            assert!(ss.bytes.iter().any(|b| *b != 0));
            let p = ss.bytes.as_ptr();
            assert!(cleared_when_freed(ss, p), "{alg:?} {what} secret left data");
        }
    }
}

#[cfg(feature = "sign")]
#[test]
fn signing_keys_are_cleared_on_drop() {
    use paraxiom_pqc::sign::{self, SignAlgorithm};

    for alg in [
        SignAlgorithm::MlDsa44,
        SignAlgorithm::MlDsa65,
        SignAlgorithm::MlDsa87,
        SignAlgorithm::SlhDsaShake128f,
        SignAlgorithm::Falcon512,
    ] {
        if alg == SignAlgorithm::Falcon512 && !sign::FALCON_SIGNING_AVAILABLE {
            continue; // no Falcon key generation on this target
        }
        let sk = sign::keypair(alg).unwrap().sk;
        assert!(sk.bytes.iter().any(|b| *b != 0));
        let p = sk.bytes.as_ptr();
        assert!(
            cleared_when_freed(sk, p),
            "{alg:?} signing key left data on the heap"
        );
    }
}

/// The two schemes the test above leaves out: SLH-DSA-SHAKE-256s and Falcon-1024.
#[cfg(feature = "sign")]
#[test]
fn remaining_signing_keys_are_cleared_on_drop() {
    use paraxiom_pqc::sign::{self, SignAlgorithm};

    for alg in [SignAlgorithm::SlhDsaShake256s, SignAlgorithm::Falcon1024] {
        if alg == SignAlgorithm::Falcon1024 && !sign::FALCON_SIGNING_AVAILABLE {
            continue;
        }
        let sk = sign::keypair(alg).unwrap().sk;
        assert!(sk.bytes.iter().any(|b| *b != 0));
        let p = sk.bytes.as_ptr();
        assert!(cleared_when_freed(sk, p), "{alg:?} signing key left data");
    }
}

/// Keys made from a quantum source go through the same type.
#[cfg(all(feature = "sign", feature = "qrng"))]
#[test]
fn qrng_signing_keys_are_cleared_on_drop() {
    use paraxiom_pqc::qrng::QrngRng;
    use paraxiom_pqc::sign::{self, SignAlgorithm};

    for alg in [
        SignAlgorithm::MlDsa44,
        SignAlgorithm::MlDsa65,
        SignAlgorithm::MlDsa87,
    ] {
        let mut rng = QrngRng::new(CountingSource(1)).unwrap();
        let sk = sign::keypair_qrng(alg, &mut rng).unwrap().sk;
        let p = sk.bytes.as_ptr();
        assert!(
            cleared_when_freed(sk, p),
            "{alg:?} QRNG signing key left data"
        );
    }
}

/// `zeroize()` empties `bytes` and clears it; the drop that follows frees zeros.
#[test]
fn explicit_zeroize_then_drop_frees_zeros() {
    use zeroize::Zeroize;
    let mut kp = kem::keypair(KemAlgorithm::MlKem512).unwrap();
    let p = kp.dk.bytes.as_ptr();
    kp.dk.zeroize();
    assert!(kp.dk.bytes.is_empty());
    assert!(cleared_when_freed(kp.dk, p));
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(64),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Whatever their contents, length and spare capacity, the three secret types clear their
    /// whole allocation, spare capacity included, before freeing it.
    #[test]
    fn any_secret_buffer_is_cleared_on_drop(
        contents in prop::collection::vec(1u8..=255, 0..300),
        spare in 0usize..64,
        which in 0u8..3,
    ) {
        prop_assume!(contents.len() + spare > 0);
        let mut bytes = Vec::with_capacity(contents.len() + spare);
        bytes.extend_from_slice(&contents);
        // Fill the spare capacity too, so that "all zero" cannot come from fresh memory.
        // SAFETY: writes within the allocation; the length is restored right after.
        unsafe {
            let cap = bytes.capacity();
            std::ptr::write_bytes(bytes.as_mut_ptr().add(bytes.len()), 0xEE, cap - bytes.len());
        }
        let p = bytes.as_ptr();
        let cleared = match which {
            0 => cleared_when_freed(DecapsulationKey { algorithm: KemAlgorithm::MlKem768, bytes }, p),
            1 => cleared_when_freed(SharedSecret { bytes }, p),
            _ => {
                #[cfg(feature = "sign")]
                {
                    use paraxiom_pqc::sign::{SignAlgorithm, SigningKey};
                    cleared_when_freed(SigningKey { algorithm: SignAlgorithm::MlDsa65, bytes }, p)
                }
                #[cfg(not(feature = "sign"))]
                {
                    cleared_when_freed(SharedSecret { bytes }, p)
                }
            }
        };
        prop_assert!(cleared);
    }
}

// ── QrngRng and the backend key objects ──────────────────────────────────────

/// A quantum source stand-in: bytes counting up from a start value.
#[cfg(feature = "qrng")]
struct CountingSource(u8);

#[cfg(feature = "qrng")]
impl paraxiom_pqc::qrng::QuantumSource for CountingSource {
    fn fill_entropy(&mut self, dest: &mut [u8]) -> Result<(), paraxiom_pqc::PqcError> {
        for b in dest {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

fn shake256(parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut out = vec![0u8; out_len];
    h.finalize_xof().read(&mut out);
    out
}

/// `QrngRng` keeps its conditioned key inline and clears it on drop. The key is recomputed here
/// from the source bytes (SHAKE256 over the seed label and 64 source bytes).
#[cfg(feature = "qrng")]
#[test]
fn qrng_key_is_gone_when_freed() {
    use paraxiom_pqc::qrng::QrngRng;
    let raw: Vec<u8> = (7u8..71).collect();
    let key = shake256(&[b"paraxiom-pqc/qrng/v1/seed", &raw], 32);
    let rng = Box::new(QrngRng::new(CountingSource(7)).unwrap());
    assert!(
        secrets_gone_when_freed(rng, &[&key]),
        "QrngRng key left in memory"
    );
}

/// ml-kem's key, as `kem::decapsulate` builds it from the 64-byte seed: d, z and the first
/// coefficients of each secret polynomial (s_hat, stored as u16) are gone after the drop. The
/// encapsulation key it also holds is public.
#[test]
fn ml_kem_backend_key_secrets_are_gone_when_freed() {
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;
    use ml_kem::KeyInit;

    macro_rules! check {
        ($P:ty, $k:expr) => {{
            let k: usize = $k;
            let seed: Vec<u8> = (0u8..64)
                .map(|i| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            let key = ml_kem::DecapsulationKey::<$P>::new(
                &ml_kem::Seed::try_from(seed.as_slice()).unwrap(),
            );
            #[allow(deprecated)]
            let expanded = key.to_expanded_bytes();
            // ByteDecode_12 of the first 16 coefficients of each of the k polynomials of s_hat.
            let mut needles: Vec<Vec<u8>> = vec![seed[..32].to_vec(), seed[32..].to_vec()];
            for poly in 0..k {
                let enc = &expanded[384 * poly..384 * poly + 24];
                let mut mem = Vec::new();
                for t in enc.chunks(3) {
                    let a = u16::from(t[0]) | (u16::from(t[1] & 0x0f) << 8);
                    let b = u16::from(t[1] >> 4) | (u16::from(t[2]) << 4);
                    mem.extend_from_slice(&a.to_ne_bytes());
                    mem.extend_from_slice(&b.to_ne_bytes());
                }
                needles.push(mem);
            }
            let refs: Vec<&[u8]> = needles.iter().map(|n| n.as_slice()).collect();
            assert!(secrets_gone_when_freed(Box::new(key), &refs), "k = {k}");
        }};
    }
    check!(ml_kem::MlKem512, 2);
    check!(ml_kem::MlKem768, 3);
    check!(ml_kem::MlKem1024, 4);
}

/// The ML-DSA fork's key objects, which `sign` builds for every signature: the 32-byte seed
/// (KeyPair) and K are gone after the drop. K is recomputed here from the seed (FIPS 204
/// Algorithm 6: rho, rho', K = H(xi || k || l, 128)). The fork's own unit test
/// `drop_clears_secret_key_material` checks every secret field.
#[cfg(feature = "sign")]
#[test]
fn ml_dsa_backend_key_secrets_are_gone_when_freed() {
    use ml_dsa::KeyGen;

    fn check<P: ml_dsa::MlDsaParams + KeyGen<KeyPair = ml_dsa::KeyPair<P>>>(k: u8, l: u8) {
        let xi = [0x3Cu8; 32];
        let expanded = shake256(&[&xi, &[k], &[l]], 128);
        let key_k = &expanded[96..128];
        let seed = ml_dsa::B32::from(xi);

        let sk = Box::new(ml_dsa::SigningKey::<P>::from_seed(&seed));
        assert!(
            secrets_gone_when_freed(sk, &[key_k]),
            "SigningKey K, k = {k}"
        );

        let kp = Box::new(<P as KeyGen>::from_seed(&seed));
        assert!(
            secrets_gone_when_freed(kp, &[&xi, key_k]),
            "KeyPair, k = {k}"
        );
    }
    check::<ml_dsa::MlDsa44>(4, 4);
    check::<ml_dsa::MlDsa65>(6, 5);
    check::<ml_dsa::MlDsa87>(8, 7);
}

/// slh-dsa's key, as `sign` parses it from our bytes: SK.seed and SK.prf are gone after the
/// drop (PK.seed and PK.root are public).
#[cfg(feature = "sign")]
#[test]
fn slh_dsa_backend_key_secrets_are_gone_when_freed() {
    fn check<P: slh_dsa::ParameterSet>(n: usize) {
        let bytes: Vec<u8> = (0..4 * n)
            .map(|i| (i as u8).wrapping_mul(29).wrapping_add(3))
            .collect();
        let sk = slh_dsa::SigningKey::<P>::try_from(bytes.as_slice()).unwrap();
        let (sk_seed, sk_prf) = (&bytes[..n], &bytes[n..2 * n]);
        assert!(
            secrets_gone_when_freed(Box::new(sk), &[sk_seed, sk_prf]),
            "n = {n}"
        );
    }
    check::<slh_dsa::Shake128f>(16);
    check::<slh_dsa::Shake256s>(32);
}

/// falcon-rs keeps its private key in a `Zeroizing<Vec<u8>>`: the buffer is all zero when freed.
#[cfg(feature = "sign")]
#[test]
fn falcon_backend_key_is_cleared_on_drop() {
    use paraxiom_pqc::sign::{self, SignAlgorithm};
    if !sign::FALCON_SIGNING_AVAILABLE {
        return;
    }
    for alg in [SignAlgorithm::Falcon512, SignAlgorithm::Falcon1024] {
        let ours = sign::keypair(alg).unwrap().sk;
        let kp = falcon::safe_api::FnDsaKeyPair::from_private_key(&ours.bytes).unwrap();
        let p = kp.private_key().as_ptr();
        assert!(
            cleared_when_freed(kp, p),
            "{alg:?} falcon-rs private key left data"
        );
    }
}
