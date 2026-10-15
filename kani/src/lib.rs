//! Kani harnesses; see README.md.
#![cfg_attr(not(kani), allow(dead_code))]

#[cfg(kani)]
mod falcon_gate {
    /// The public constant agrees with the target condition it documents.
    #[kani::proof]
    fn falcon_gate_matches_target() {
        let expected = (cfg!(any(target_arch = "x86", target_arch = "x86_64"))
            && cfg!(target_feature = "sse2"))
            || (cfg!(target_arch = "aarch64") && cfg!(target_feature = "neon"));
        assert_eq!(paraxiom_pqc::sign::FALCON_SIGNING_AVAILABLE, expected);
    }
}

/// What `zeroize()` leaves in the allocation of the three secret types.
///
/// An earlier version of these harnesses checked the buffer inside a `#[global_allocator]` at
/// deallocation. Kani 0.67 models heap memory itself and does not call a global allocator, so
/// those checks never ran (the "buffer was released" assertion failed). These harnesses instead
/// read the allocation, through a raw pointer, after `zeroize()` and before the value is
/// dropped. The `Drop` impl that calls `zeroize()` comes from `#[derive(ZeroizeOnDrop)]`;
/// that it runs and clears the buffer at deallocation is checked at run time by
/// tests/zeroize.rs (a watching allocator), not here.
#[cfg(kani)]
mod zeroize_clears_allocation {
    use paraxiom_pqc::kem::{DecapsulationKey, KemAlgorithm, SharedSecret};
    use paraxiom_pqc::sign::{SignAlgorithm, SigningKey};
    use zeroize::Zeroize;

    const MAX_LEN: usize = 4;
    const MAX_SPARE: usize = 2;

    /// A buffer of symbolic length (up to MAX_LEN), symbolic contents and symbolic spare
    /// capacity (up to MAX_SPARE), with the spare capacity filled with symbolic bytes too.
    fn any_buffer() -> Vec<u8> {
        let len: usize = kani::any();
        let spare: usize = kani::any();
        kani::assume(len <= MAX_LEN && spare <= MAX_SPARE && len + spare > 0);
        let mut v: Vec<u8> = Vec::with_capacity(len + spare);
        let mut i = 0;
        while i < len + spare {
            v.push(kani::any());
            i += 1;
        }
        v.truncate(len); // keeps the bytes past len in the allocation
        v
    }

    /// Every byte of the `cap`-byte allocation at `p` is zero. The allocation must be live.
    fn all_zero(p: *const u8, cap: usize) {
        let mut i = 0;
        while i < cap {
            // SAFETY: `p` is a live allocation of `cap` initialised bytes (see callers).
            assert!(
                unsafe { *p.add(i) } == 0,
                "a byte of the allocation was not cleared"
            );
            i += 1;
        }
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn decapsulation_key_zeroize_clears_every_byte() {
        let mut dk = DecapsulationKey {
            algorithm: KemAlgorithm::MlKem768,
            bytes: any_buffer(),
        };
        let (p, cap) = (dk.bytes.as_ptr(), dk.bytes.capacity());
        dk.zeroize();
        // zeroize() keeps the allocation (it clears and empties the Vec), so `p` is still live.
        assert!(dk.bytes.as_ptr() == p && dk.bytes.capacity() == cap && dk.bytes.is_empty());
        all_zero(p, cap);
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn shared_secret_zeroize_clears_every_byte() {
        let mut ss = SharedSecret {
            bytes: any_buffer(),
        };
        let (p, cap) = (ss.bytes.as_ptr(), ss.bytes.capacity());
        ss.zeroize();
        assert!(ss.bytes.as_ptr() == p && ss.bytes.capacity() == cap && ss.bytes.is_empty());
        all_zero(p, cap);
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn signing_key_zeroize_clears_every_byte() {
        let mut sk = SigningKey {
            algorithm: SignAlgorithm::MlDsa65,
            bytes: any_buffer(),
        };
        let (p, cap) = (sk.bytes.as_ptr(), sk.bytes.capacity());
        sk.zeroize();
        assert!(sk.bytes.as_ptr() == p && sk.bytes.capacity() == cap && sk.bytes.is_empty());
        all_zero(p, cap);
    }

    /// Control: `clear()` on a plain Vec does not clear its bytes, so the check must fail.
    #[kani::proof]
    #[kani::unwind(8)]
    #[kani::should_panic]
    fn control_vec_clear_does_not_clear_bytes() {
        let mut v = any_buffer();
        let (p, cap) = (v.as_ptr(), v.capacity());
        v.clear();
        all_zero(p, cap);
    }
}

/// Length checks on the parsing entry points, and the combiner's policy rules.
///
/// The length runs over a range in a loop, concrete in each iteration, with symbolic contents;
/// the algorithm is concrete too. With a symbolic length (or a symbolic algorithm label) CBMC
/// also explores the cryptographic code that the length check rules out, and the harnesses did
/// not finish: the symbolic Falcon harness was stopped after more than 30 minutes.
///
/// Two harnesses written in this concrete form were run on 2026-10-15 and timed out at the
/// 15-minute harness timeout, and were removed: `kem::decapsulate` refusing ML-KEM-768 seeds of
/// lengths 0 to 80 other than 64 (it reached length 10), and ML-DSA-65 signing refusing seeds of
/// lengths 0 to 40 other than 32 through the three signing functions (it reached length 11).
/// In both, CBMC still explored the backend (SHA-3, key expansion). Wrong lengths there are
/// covered by the property tests (`kem_wrong_lengths_are_errors`,
/// `wrong_length_signing_key_is_an_error`) and the fuzz targets, which test and do not prove.
#[cfg(kani)]
mod length_checks {
    use paraxiom_pqc::combiner::{Mechanism, Policy, Secret, MIN_SECRET_LEN};
    use paraxiom_pqc::sign::{self, SignAlgorithm, Signature, VerificationKey};

    /// `len` bytes (concrete) of symbolic contents, `len <= N`.
    fn any_bytes_of_len<const N: usize>(len: usize) -> Vec<u8> {
        let all: [u8; N] = kani::any();
        all[..len].to_vec()
    }

    /// `falcon::verify` refuses a public key of each length 0 to 32 (Falcon-512 keys are 897
    /// bytes), whatever its contents (header byte included) and an 8-byte symbolic signature;
    /// so does `sign::verify` under each Falcon label (`Ok(false)`). The length is concrete in
    /// each loop iteration.
    #[kani::proof]
    #[kani::unwind(34)]
    fn falcon_verify_refuses_a_short_key() {
        let mut len = 0;
        while len <= 32 {
            let vk = any_bytes_of_len::<32>(len);
            let sig = any_bytes_of_len::<8>(8);
            assert!(!paraxiom_pqc::falcon::verify(&vk, b"m", &sig));
            for label in [SignAlgorithm::Falcon512, SignAlgorithm::Falcon1024] {
                let r = sign::verify(
                    &VerificationKey {
                        algorithm: label,
                        bytes: vk.clone(),
                    },
                    b"m",
                    &Signature {
                        algorithm: label,
                        bytes: sig.clone(),
                    },
                );
                assert!(matches!(r, Ok(false)));
            }
            len += 1;
        }
    }

    /// ML-DSA-44 verification refuses a signature of each length 0 to 16 (the right one is
    /// 2420), with any contents. The unwinding bound is 2421 because ml-dsa builds a
    /// 2420-element array while parsing, whatever the input length.
    #[kani::proof]
    #[kani::unwind(2421)]
    fn ml_dsa_verify_refuses_a_signature_of_the_wrong_length() {
        let mut len = 0;
        while len <= 16 {
            let sig = Signature {
                algorithm: SignAlgorithm::MlDsa44,
                bytes: any_bytes_of_len::<16>(len),
            };
            let vk = VerificationKey {
                algorithm: SignAlgorithm::MlDsa44,
                bytes: Vec::new(),
            };
            assert!(sign::verify(&vk, b"m", &sig).is_err());
            len += 1;
        }
    }

    /// SLH-DSA-SHAKE-128f verification refuses a verification key of each length 0 to 40 other
    /// than 32, with any contents.
    #[kani::proof]
    #[kani::unwind(42)]
    fn slh_dsa_verify_refuses_a_key_of_the_wrong_length() {
        let mut len = 0;
        while len <= 40 {
            if len != 32 {
                let vk = VerificationKey {
                    algorithm: SignAlgorithm::SlhDsaShake128f,
                    bytes: any_bytes_of_len::<40>(len),
                };
                let sig = Signature {
                    algorithm: SignAlgorithm::SlhDsaShake128f,
                    bytes: Vec::new(),
                };
                assert!(sign::verify(&vk, b"m", &sig).is_err());
            }
            len += 1;
        }
    }

    fn any_mechanism() -> Mechanism {
        match kani::any::<u8>() % 5 {
            0 => Mechanism::Qkd,
            1 => Mechanism::MlKem512,
            2 => Mechanism::MlKem768,
            3 => Mechanism::MlKem1024,
            _ => Mechanism::PreShared,
        }
    }

    /// `Policy::new` on any list of up to 4 mechanisms (symbolic length and contents):
    /// accepted exactly when the list is not empty and has no duplicate, and then it keeps the
    /// list as given.
    #[kani::proof]
    #[kani::unwind(6)]
    fn policy_new_accepts_exactly_nonempty_lists_without_duplicates() {
        let all = [
            any_mechanism(),
            any_mechanism(),
            any_mechanism(),
            any_mechanism(),
        ];
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let list = &all[..n];
        let mut dup = false;
        let mut i = 0;
        while i < n {
            let mut j = 0;
            while j < i {
                if list[i] == list[j] {
                    dup = true;
                }
                j += 1;
            }
            i += 1;
        }
        match Policy::new(list) {
            Ok(p) => {
                assert!(n > 0 && !dup);
                assert!(p.mechanisms() == list);
            }
            Err(_) => assert!(n == 0 || dup),
        }
    }

    /// `Policy::combine`, for the policy (QKD, ML-KEM-768), refuses secrets that do not match
    /// it one for one: every count 0 to 3 and every pair of mechanisms other than the policy's
    /// own (with lengths that would otherwise be accepted), a QKD secret of each length 0 to 15
    /// (MIN_SECRET_LEN is 16), and an ML-KEM secret of each length 0 to 40 other than 32. The
    /// secret bytes are symbolic; counts, mechanisms and lengths are enumerated.
    #[kani::proof]
    #[kani::unwind(42)]
    fn combine_refuses_secrets_that_do_not_match_the_policy() {
        const ALL: [Mechanism; 5] = [
            Mechanism::Qkd,
            Mechanism::MlKem512,
            Mechanism::MlKem768,
            Mechanism::MlKem1024,
            Mechanism::PreShared,
        ];
        let policy = Policy::new(&[Mechanism::Qkd, Mechanism::MlKem768]).unwrap();
        let a: [u8; 40] = kani::any();
        let b: [u8; 40] = kani::any();
        for ma in ALL {
            for mb in ALL {
                let pool = [
                    Secret::new(ma, &a[..16]),
                    Secret::new(mb, &b[..32]),
                    Secret::new(ma, &a[..16]),
                ];
                for count in 0..=3 {
                    if count == 2 && ma == Mechanism::Qkd && mb == Mechanism::MlKem768 {
                        continue;
                    }
                    assert!(policy.combine(&pool[..count], b"").is_err());
                }
            }
        }
        let mut len = 0;
        while len <= 40 {
            if len < MIN_SECRET_LEN {
                let s = [
                    Secret::new(Mechanism::Qkd, &a[..len]),
                    Secret::new(Mechanism::MlKem768, &b[..32]),
                ];
                assert!(policy.combine(&s, b"").is_err());
            }
            if len != 32 {
                let s = [
                    Secret::new(Mechanism::Qkd, &a[..16]),
                    Secret::new(Mechanism::MlKem768, &b[..len]),
                ];
                assert!(policy.combine(&s, b"").is_err());
            }
            len += 1;
        }
    }
}
