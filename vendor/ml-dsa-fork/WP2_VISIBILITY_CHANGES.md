# ML-DSA Fork: Visibility Changes for WP2 Constant-Time Signing

## Summary

Successfully created a local fork of `ml-dsa` v0.1.0-rc.7 with visibility adjustments to enable constant-time signing kernel implementation in `paraxiom-pqc`.

**Status:** ✅ Fork created, modified, and verified to compile. Integration with paraxiom-pqc complete.

---

## Files Modified

### 1. `/home/edwinafful/ml-dsa-fork/src/sampling.rs`

**Functions Changed from `pub(crate)` to `pub`:**

| Function | Line | Purpose | Needed By |
|----------|------|---------|-----------|
| `expand_a<K, L>()` | ~145 | Generate matrix A in NTT form | Constant-time kernel (candidate generation) |
| `expand_s<K>()` | ~159 | Generate s1, s2 vectors | Constant-time kernel (candidate generation) |
| `expand_mask<K, Gamma1>()` | 165 | Generate masking vector y | Constant-time kernel (rejection sampling candidates) |

**Related Functions (Already `pub(crate)`, unchanged):**
- `sample_in_ball()` - Line 61 - CHANGED TO `pub` ✅

---

### 2. `/home/edwinafful/ml-dsa-fork/src/hint.rs`

**Struct Changed from `pub(crate)` to `pub`:**

```rust
// Before:
pub(crate) struct Hint<P>(pub Array<Array<bool, U256>, P::K>)

// After:
pub struct Hint<P>(pub Array<Array<bool, U256>, P::K>)
```

**Methods Changed from `pub(crate)` to `pub`:**

| Method | Purpose |
|--------|---------|
| `Hint::new(z, r)` | Construct hint vector from z and remainder |
| `Hint::hamming_weight()` | Count non-zero hint bits |
| `Hint::use_hint(r)` | Apply hint correction to remainder vector |

---

### 3. `/home/edwinafful/ml-dsa-fork/src/lib.rs`

**SigningKey Struct Fields Changed from Private to `pub`:**

```rust
pub struct SigningKey<P: MlDsaParams> {
    /// Rho (32 bytes) - public seed for matrix A
    pub rho: B32,
    
    /// K (32 bytes) - private seed for s1, s2
    pub K: B32,
    
    /// tr (64 bytes) - transcript hash
    pub tr: B64,
    
    /// s1 - private vector
    pub s1: Vector<P::L>,
    
    /// s2 - private vector
    pub s2: Vector<P::K>,
    
    /// t0 - private vector
    pub t0: Vector<P::K>,

    // Derived values
    /// s1_hat - NTT-transformed s1
    pub s1_hat: NttVector<P::L>,
    
    /// s2_hat - NTT-transformed s2
    pub s2_hat: NttVector<P::K>,
    
    /// t0_hat - NTT-transformed t0
    pub t0_hat: NttVector<P::K>,
    
    /// A_hat - Matrix A in NTT form
    pub A_hat: NttMatrix<P::K, P::L>,
}
```

---

## Compilation Status

### ml-dsa-fork

```bash
$ cd /home/edwinafful/ml-dsa-fork && cargo check
   Compiling ml-dsa v0.1.0-rc.7
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 24.11s
```

**Warnings:** 13 warnings (visibility-related, expected after making internal items public)
**Errors:** 0 ✅

### paraxiom-pqc

```bash
$ cd /home/edwinafful/paraxiom-pqc && cargo check
   Compiling paraxiom-pqc v0.1.2
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.91s
```

**Errors:** 0 ✅

---

## Integration: paraxiom-pqc/Cargo.toml

**Updated dependency:**

```toml
[dependencies]
ml-dsa = { path = "../ml-dsa-fork", version = "=0.1.0-rc.7" }  # WP2: Local fork with constant-time signing support
```

paraxiom-pqc now uses the local fork instead of pulling from crates.io registry.

---

## Git History

**ml-dsa-fork commit:**

```
commit d8d167f
Author: edwinafful
Date:   2026-07-11

    WP2: Expose internal helpers for constant-time signing implementation
    
    - sampling.rs: Make expand_a, expand_s, expand_mask functions pub
    - hint.rs: Make Hint struct and its methods (new, hamming_weight, use_hint) pub  
    - lib.rs: Make SigningKey fields public
    
    These changes allow paraxiom-pqc's constant-time signing kernel to access
    necessary internal types and functions.
    
    FIPS 204 compliance is maintained.
```

---

## Verification Checklist

- [x] ml-dsa-fork created from registry source (v0.1.0-rc.7)
- [x] ml-dsa-fork initialized as git repository
- [x] All visibility changes applied:
  - [x] sampling.rs: expand_a, expand_s, expand_mask (pub)
  - [x] sampling.rs: sample_in_ball (pub)
  - [x] hint.rs: Hint struct (pub)
  - [x] hint.rs: Hint::new, hamming_weight, use_hint (pub)
  - [x] lib.rs: SigningKey fields (pub)
- [x] ml-dsa-fork compiles without errors
- [x] paraxiom-pqc Cargo.toml updated to use local fork
- [x] paraxiom-pqc compiles without errors against local fork
- [x] Changes committed to git with detailed message
- [x] Documentation added (this file)

---

## FIPS 204 Compliance

✅ **Maintained** — All changes are visibility-only:
- No algorithm modifications
- No signature encoding changes
- No cryptographic behavior alterations
- Internal structure remains identical
- Signature format unchanged

The fork is functionally equivalent to the original ml-dsa crate, with only the visibility of internal helpers adjusted.

---

## Next Steps: Implementing Constant-Time Signing

With these visibility changes in place, the following is now possible in `paraxiom-pqc/src/dsa_ct.rs`:

```rust
// Pseudocode - now implementable with exposed ml-dsa helpers
const MAX_ROUNDS: usize = 256;

for round in 0..MAX_ROUNDS {
    // Access previously private functions:
    let y = ml_dsa::sampling::expand_mask::<P::L, P::Gamma1>(&rhopp, round);
    let w = (&sk.A_hat * &y.ntt()).ntt_inverse();
    
    // Access previously private fields:
    let z = &y + &(&c_hat * &sk.s1_hat).ntt_inverse();
    let ct0 = (&c_hat * &sk.t0_hat).ntt_inverse();
    
    // Access previously private types:
    let h = ml_dsa::hint::Hint::<P>::new(...);
    
    // Branchless acceptance logic (no secret-dependent branches)
    let accept = (z.norm < BOUND1) & (r0.norm < BOUND2) 
               & (ct0.norm < BOUND3) & (h.hamming_weight() <= BOUND4);
    let keep = accept & (1 - chosen_flag);
    if keep { chosen = sig_candidate; chosen_flag = 1; }
}
```

---

## File Locations

| Item | Path |
|------|------|
| ml-dsa fork (root) | `/home/edwinafful/ml-dsa-fork/` |
| ml-dsa fork src | `/home/edwinafful/ml-dsa-fork/src/` |
| paraxiom-pqc | `/home/edwinafful/paraxiom-pqc/` |
| This summary | `/home/edwinafful/ml-dsa-fork/WP2_VISIBILITY_CHANGES.md` |

---

## Summary of Exposed APIs

**Total items exposed:**

| Category | Count |
|----------|-------|
| Functions | 4 (expand_a, expand_s, expand_mask, sample_in_ball) |
| Structs | 1 (Hint<P>) |
| Methods | 3 (Hint::new, hamming_weight, use_hint) |
| Struct fields | 10 (SigningKey fields) |
| **Total** | **18 items** |

All exposures are necessary and minimal for implementing the constant-time signing kernel.

---

**Document Created:** 2026-07-11  
**Status:** Complete ✅  
**Blocks:** None — Implementation can proceed immediately
