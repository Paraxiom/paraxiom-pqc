//! The secret types must clear their heap buffers before the memory goes back to the allocator.
//!
//! This test binary installs a global allocator that wraps the system allocator. When the one
//! watched buffer is freed, it looks at the bytes first and records whether they were all zero.
//! Each test watches the buffer of one secret value, drops the value, and reads the verdict.
//! A plain `Vec` serves as the control: it must be reported as not cleared.

use paraxiom_pqc::kem::{self, KemAlgorithm};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

struct WatchingAllocator;

/// Address of the watched buffer, 0 when nothing is watched.
static WATCHED: AtomicUsize = AtomicUsize::new(0);
/// 0: not freed yet, 1: freed and all zero, 2: freed with data left in it.
static VERDICT: AtomicU8 = AtomicU8::new(0);
/// Tests run in parallel; one watch at a time.
static ONE_WATCH: Mutex<()> = Mutex::new(());

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
            let cleared = bytes.iter().all(|b| *b == 0);
            VERDICT.store(if cleared { 1 } else { 2 }, Ordering::SeqCst);
            WATCHED.store(0, Ordering::SeqCst);
        }
        // SAFETY: forwarded unchanged to the system allocator that produced `ptr`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WatchingAllocator = WatchingAllocator;

/// Drops `value` and reports whether the heap buffer at `buffer` was all zero when freed.
fn cleared_when_freed<T>(value: T, buffer: *const u8) -> bool {
    let _one = ONE_WATCH.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    VERDICT.store(0, Ordering::SeqCst);
    WATCHED.store(buffer as usize, Ordering::SeqCst);
    drop(value);
    WATCHED.store(0, Ordering::SeqCst);
    match VERDICT.load(Ordering::SeqCst) {
        1 => true,
        2 => false,
        _ => panic!("dropping the value did not free the watched buffer"),
    }
}

#[test]
fn control_a_plain_vec_is_not_cleared() {
    let v = vec![0xA5u8; 64];
    let p = v.as_ptr();
    assert!(!cleared_when_freed(v, p), "the harness must see data left in a plain Vec");
}

#[test]
fn decapsulation_key_is_cleared_on_drop() {
    for alg in [KemAlgorithm::MlKem512, KemAlgorithm::MlKem768, KemAlgorithm::MlKem1024] {
        let dk = kem::keypair(alg).unwrap().dk;
        assert!(dk.bytes.iter().any(|b| *b != 0));
        let p = dk.bytes.as_ptr();
        assert!(cleared_when_freed(dk, p), "{alg:?} decapsulation key left data on the heap");
    }
}

#[test]
fn shared_secrets_are_cleared_on_drop() {
    let kp = kem::keypair(KemAlgorithm::MlKem768).unwrap();
    let (ct, ss_sender) = kem::encapsulate(&kp.ek).unwrap();
    let ss_receiver = kem::decapsulate(&kp.dk, &ct).unwrap();
    assert_eq!(ss_sender.bytes, ss_receiver.bytes);

    let p = ss_sender.bytes.as_ptr();
    assert!(cleared_when_freed(ss_sender, p), "encapsulated secret left data on the heap");
    let p = ss_receiver.bytes.as_ptr();
    assert!(cleared_when_freed(ss_receiver, p), "decapsulated secret left data on the heap");
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
        let sk = sign::keypair(alg).unwrap().sk;
        assert!(sk.bytes.iter().any(|b| *b != 0));
        let p = sk.bytes.as_ptr();
        assert!(cleared_when_freed(sk, p), "{alg:?} signing key left data on the heap");
    }
}
