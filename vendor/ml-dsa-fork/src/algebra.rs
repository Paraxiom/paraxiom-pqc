use hybrid_array::{
    typenum::{Shleft, Unsigned, U1, U13},
    ArraySize,
};
use module_lattice::{Field, Truncate};

module_lattice::define_field!(BaseField, u32, u64, u128, 8_380_417);

pub(crate) type Int = <BaseField as Field>::Int;

pub(crate) type Elem = module_lattice::Elem<BaseField>;
pub(crate) type Polynomial = module_lattice::Polynomial<BaseField>;
pub(crate) type Vector<K> = module_lattice::Vector<BaseField, K>;
pub(crate) type NttPolynomial = module_lattice::NttPolynomial<BaseField>;
pub(crate) type NttVector<K> = module_lattice::NttVector<BaseField, K>;
pub(crate) type NttMatrix<K, L> = module_lattice::NttMatrix<BaseField, K, L>;

// We require modular reduction for three moduli: q, 2^d, and 2 * gamma2.  All three of these are
// greater than sqrt(q), which means that a number reduced mod q will always be less than M^2,
// which means that barrett reduction will work.
pub(crate) trait BarrettReduce: Unsigned {
    const SHIFT: usize;
    const MULTIPLIER: u64;

    fn reduce(x: u32) -> u32 {
        let m = Self::U64;
        let x: u64 = x.into();
        let quotient = (x * Self::MULTIPLIER) >> Self::SHIFT;
        let remainder = x - quotient * m;

        // Use wrapping arithmetic to avoid debug-mode panics
        // mask = 0xFFFFFFFF if remainder < m, else 0
        let mask = ((remainder.wrapping_sub(m) as i64) >> 63) as u64;
        let result = (remainder & mask) | (remainder.wrapping_sub(m) & !mask);
        result as u32
    }
}

impl<M> BarrettReduce for M
where
    M: Unsigned,
{
    #[allow(clippy::as_conversions)]
    const SHIFT: usize = 2 * (M::U64.ilog2() + 1) as usize;
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const MULTIPLIER: u64 = (1 << Self::SHIFT) / M::U64;
}

pub(crate) trait Decompose {
    fn decompose<TwoGamma2: Unsigned>(self) -> (Elem, Elem);
}

/// Constant-time division by a compile-time constant divisor.
///
/// This trait provides a constant-time alternative to the hardware division
/// instruction, which has variable timing based on operand values.
/// Uses Barrett reduction to compute `x / M` where M is a compile-time constant.
pub(crate) trait ConstantTimeDiv: Unsigned {
    /// Bit shift for Barrett reduction, chosen to provide sufficient precision
    const CT_DIV_SHIFT: usize;
    /// Precomputed multiplier: ceil(2^SHIFT / M)
    const CT_DIV_MULTIPLIER: u64;

    /// Perform constant-time division of x by `Self::U32`
    /// Requires: x < Q (the field modulus, ~2^23)
    #[allow(clippy::inline_always)] // Required for constant-time guarantees in crypto code
    #[inline(always)]
    fn ct_div(x: u32) -> u32 {
        // Barrett reduction: q = (x * MULTIPLIER) >> SHIFT
        // This gives us floor(x / M) for x < 2^SHIFT / MULTIPLIER * M
        let x64 = u64::from(x);
        let quotient = (x64 * Self::CT_DIV_MULTIPLIER) >> Self::CT_DIV_SHIFT;
        // SAFETY: quotient is guaranteed to fit in u32 because:
        // - x < Q (~2^23), so quotient = x / M < x < 2^23 < 2^32
        #[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
        let result = quotient as u32;
        result
    }
}

impl<M> ConstantTimeDiv for M
where
    M: Unsigned,
{
    // Use a shift that provides enough precision for the ML-DSA field (Q ~ 2^23)
    // We need SHIFT > log2(Q) + log2(M) to ensure accuracy
    // With Q < 2^24 and M < 2^20, SHIFT = 48 is sufficient
    const CT_DIV_SHIFT: usize = 48;

    // Precompute the multiplier at compile time
    // We add (M-1) before dividing to get ceiling division, ensuring we never underestimate
    #[allow(clippy::integer_division_remainder_used, reason = "constant")]
    const CT_DIV_MULTIPLIER: u64 = (1u64 << Self::CT_DIV_SHIFT).div_ceil(M::U64);
}

impl Decompose for Elem {
    // Algorithm 36 Decompose
    //
    // This implementation uses constant-time division to avoid timing side-channels.
    // The original algorithm used hardware division which has variable timing based
    // on operand values, potentially leaking secret information during signing.
    fn decompose<TwoGamma2: Unsigned>(self) -> (Elem, Elem) {
        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus::<TwoGamma2>();

        let diff = r_plus - r0;
        let is_q_minus_1 = diff.0 == BaseField::Q - 1;
        // mask = 0xFFFFFFFF if special case (diff == Q-1), 0 otherwise
        let mask = (is_q_minus_1 as u32).wrapping_neg();

        // If diff == Q-1: r1 = 0, r0 = r0 - 1
        // Else: r1 = diff / (2*gamma2), r0 = r0
        let r1_special = Elem::new(0);
        let r1_normal = Elem::new(TwoGamma2::ct_div(diff.0));
        // mask selects special case when 1, normal case when 0
        let r1 = Elem::new((r1_special.0 & mask) | (r1_normal.0 & !mask));

        let r0_special = r0 - Elem::new(1);
        let r0_normal = r0;
        let r0_final = Elem::new((r0_special.0 & mask) | (r0_normal.0 & !mask));

        (r1, r0_final)
    }
}

#[allow(clippy::module_name_repetitions)] // I can't think of a better name
pub(crate) trait AlgebraExt: Sized {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self;
    fn infinity_norm(&self) -> Int;
    fn power2round(&self) -> (Self, Self);
    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self;
    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self;
}

impl AlgebraExt for Elem {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        let raw_mod = Elem::new(M::reduce(self.0));
        let half_m = M::U32 >> 1;
        // Constant-time mask: 0xFFFFFFFF if raw_mod <= half_m, else 0
        // Using (a <= b) -> ((a - b - 1) as i32 >> 31) as u32
        let mask = ((raw_mod.0 as u32).wrapping_sub(half_m + 1) as i32 >> 31) as u32;
        // For negative case: (raw_mod - M) mod Q = raw_mod + Q - M
        let sub_result = raw_mod.0.wrapping_add(BaseField::Q).wrapping_sub(M::U32);
        let result = (raw_mod.0 & mask) | (sub_result & !mask);
        Elem::new(result)
    }

    fn infinity_norm(&self) -> u32 {
        let half_q = BaseField::Q >> 1;
        // Constant-time mask: 0xFFFFFFFF if self.0 <= half_q, else 0
        let mask = ((self.0 as u32).wrapping_sub(half_q + 1) as i32 >> 31) as u32;
        (self.0 & mask) | ((BaseField::Q - self.0) & !mask)
    }

    fn power2round(&self) -> (Self, Self) {
        type D = U13;
        type Pow2D = Shleft<U1, D>;

        let r_plus = self.clone();
        let r0 = r_plus.mod_plus_minus::<Pow2D>();
        let r1 = Elem::new((r_plus - r0).0 >> D::USIZE);

        (r1, r0)
    }

    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        self.decompose::<TwoGamma2>().0
    }

    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        self.decompose::<TwoGamma2>().1
    }
}

impl AlgebraExt for Polynomial {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(AlgebraExt::mod_plus_minus::<M>).collect())
    }

    fn infinity_norm(&self) -> u32 {
        self.0.iter().map(AlgebraExt::infinity_norm).max().unwrap()
    }

    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }

    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::high_bits::<TwoGamma2>)
                .collect(),
        )
    }

    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::low_bits::<TwoGamma2>)
                .collect(),
        )
    }
}

impl<K: ArraySize> AlgebraExt for Vector<K> {
    fn mod_plus_minus<M: Unsigned>(&self) -> Self {
        Self(self.0.iter().map(AlgebraExt::mod_plus_minus::<M>).collect())
    }

    fn infinity_norm(&self) -> u32 {
        self.0.iter().map(AlgebraExt::infinity_norm).max().unwrap()
    }

    fn power2round(&self) -> (Self, Self) {
        let mut r1 = Self::default();
        let mut r0 = Self::default();

        for (i, x) in self.0.iter().enumerate() {
            (r1.0[i], r0.0[i]) = x.power2round();
        }

        (r1, r0)
    }

    fn high_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::high_bits::<TwoGamma2>)
                .collect(),
        )
    }

    fn low_bits<TwoGamma2: Unsigned>(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(AlgebraExt::low_bits::<TwoGamma2>)
                .collect(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::integer_division_remainder_used, reason = "tests")]
mod test {
    use super::*;

    use crate::{MlDsa65, ParameterSet};

    type Mod = <MlDsa65 as ParameterSet>::TwoGamma2;
    const MOD: u32 = Mod::U32;
    const MOD_ELEM: Elem = Elem::new(MOD);

    #[test]
    fn mod_plus_minus() {
        for x in 0..MOD {
            // BaseField::Q {
            let x = Elem::new(x);
            let x0 = x.mod_plus_minus::<Mod>();

            // Outputs from mod+- should be in the half-open interval (-gamma2, gamma2]
            let positive_bound = x0.0 <= MOD / 2;
            let negative_bound = x0.0 > BaseField::Q - MOD / 2;
            assert!(positive_bound || negative_bound);

            // The output should be equivalent to the input, mod 2 * gamma2.  We add 2 * gamma2
            // before comparing so that both values are "positive", avoiding interactions between
            // the mod-Q and mod-M operations.
            let xn = x + MOD_ELEM;
            let x0n = x0 + MOD_ELEM;
            assert_eq!(xn.0 % MOD, x0n.0 % MOD);
        }
    }

    #[test]
    fn decompose() {
        for x in 0..MOD {
            let x = Elem::new(x);
            let (x1, x0) = x.decompose::<Mod>();

            // The low-order output from decompose() is a mod+- output, optionally minus one.  So
            // they should be in the closed interval [-gamma2, gamma2].
            let positive_bound = x0.0 <= MOD / 2;
            let negative_bound = x0.0 >= BaseField::Q - MOD / 2;
            assert!(positive_bound || negative_bound);

            // The low-order and high-order outputs should combine to form the input.
            let xx = (MOD * x1.0 + x0.0) % BaseField::Q;
            assert_eq!(xx, x.0);
        }
    }

    #[test]
    fn barrett_reduce_boundary() {
        let m_minus_1 = Mod::U32 - 1;
        assert_eq!(Mod::reduce(m_minus_1), m_minus_1);
        assert_eq!(Mod::reduce(Mod::U32), 0);
        assert_eq!(Mod::reduce(Mod::U32 + 1), 1);
        assert_eq!(Mod::reduce(2 * Mod::U32 - 1), m_minus_1);
        assert_eq!(Mod::reduce(2 * Mod::U32), 0);
    }

    #[test]
    fn constant_time_div_accuracy() {
        for x in 0..1000 {
            assert_eq!(Mod::ct_div(x), x / Mod::U32);
        }
        for x in (BaseField::Q - 1000)..BaseField::Q {
            assert_eq!(Mod::ct_div(x), x / Mod::U32);
        }
    }

    #[test]
    fn decompose_edge_case() {
        let q_minus_1 = Elem::new(BaseField::Q - 1);
        let (r1, r0) = q_minus_1.decompose::<Mod>();
        let reconstructed = (MOD * r1.0 + r0.0) % BaseField::Q;
        assert_eq!(reconstructed, q_minus_1.0);
    }

    #[test]
    fn high_low_bits_consistency() {
        for x in [0, 1, MOD / 2, MOD - 1, MOD, MOD + 1, BaseField::Q - 1] {
            let elem = Elem::new(x);
            let (decomp_high, decomp_low) = elem.decompose::<Mod>();
            assert_eq!(elem.high_bits::<Mod>(), decomp_high);
            assert_eq!(elem.low_bits::<Mod>(), decomp_low);
        }
    }
}
