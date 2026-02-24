//! P-256 specialized Jacobian point arithmetic.
//!
//! Uses [`P256FieldElement`] for all field operations, avoiding BigNum heap
//! allocation overhead. Combined with a w=4 fixed-window scalar multiplication,
//! this provides a significant speedup for ECDSA/ECDH P-256.

use super::p256_field::P256FieldElement;
use hitls_bignum::BigNum;
use hitls_types::CryptoError;

/// P-256 base point Gx (big-endian).
const P256_GX: [u8; 32] = [
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
];

/// P-256 base point Gy (big-endian).
const P256_GY: [u8; 32] = [
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
];

/// A P-256 point in Jacobian projective coordinates.
///
/// Represents affine point (X/Z^2, Y/Z^3). Point at infinity has Z = 0.
#[derive(Clone, Copy)]
pub(crate) struct P256JacobianPoint {
    x: P256FieldElement,
    y: P256FieldElement,
    z: P256FieldElement,
}

impl P256JacobianPoint {
    /// Point at infinity (identity element).
    pub fn infinity() -> Self {
        Self {
            x: P256FieldElement::ONE,
            y: P256FieldElement::ONE,
            z: P256FieldElement::ZERO,
        }
    }

    /// Create from affine coordinates (Z = 1).
    pub fn from_affine(x: &P256FieldElement, y: &P256FieldElement) -> Self {
        Self {
            x: *x,
            y: *y,
            z: P256FieldElement::ONE,
        }
    }

    /// Check if this is the point at infinity.
    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Convert to affine coordinates. Returns `None` if at infinity.
    pub fn to_affine(self) -> Option<(P256FieldElement, P256FieldElement)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = self.z.inv();
        let z_inv2 = z_inv.sqr();
        let z_inv3 = z_inv2.mul(&z_inv);
        Some((self.x.mul(&z_inv2), self.y.mul(&z_inv3)))
    }
}

/// Point doubling: R = 2A.
///
/// Optimized for P-256 (a = -3): uses M = 3*(X+Z^2)*(X-Z^2).
fn p256_point_double(a: &P256JacobianPoint) -> P256JacobianPoint {
    if a.is_infinity() || a.y.is_zero() {
        return P256JacobianPoint::infinity();
    }

    // M = 3*(X + Z^2)*(X - Z^2)  [since a = -3]
    let z_sq = a.z.sqr();
    let x_plus = a.x.add(&z_sq);
    let x_minus = a.x.sub(&z_sq);
    let m3 = x_plus.mul(&x_minus);
    let m = m3.add(&m3).add(&m3);

    // S = 4*X*Y^2
    let y_sq = a.y.sqr();
    let xy2 = a.x.mul(&y_sq);
    let s = xy2.add(&xy2).add(&xy2).add(&xy2);

    // X3 = M^2 - 2*S
    let m_sq = m.sqr();
    let x3 = m_sq.sub(&s).sub(&s);

    // Y3 = M*(S - X3) - 8*Y^4
    let y4 = y_sq.sqr();
    let y4_2 = y4.add(&y4);
    let y4_4 = y4_2.add(&y4_2);
    let y4_8 = y4_4.add(&y4_4);
    let y3 = m.mul(&s.sub(&x3)).sub(&y4_8);

    // Z3 = 2*Y*Z
    let yz = a.y.mul(&a.z);
    let z3 = yz.add(&yz);

    P256JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Point addition: R = A + B.
fn p256_point_add(a: &P256JacobianPoint, b: &P256JacobianPoint) -> P256JacobianPoint {
    if a.is_infinity() {
        return *b;
    }
    if b.is_infinity() {
        return *a;
    }

    let z2_sq = b.z.sqr();
    let u1 = a.x.mul(&z2_sq);
    let z1_sq = a.z.sqr();
    let u2 = b.x.mul(&z1_sq);

    let s1 = a.y.mul(&z2_sq.mul(&b.z));
    let s2 = b.y.mul(&z1_sq.mul(&a.z));

    let h = u2.sub(&u1);
    let r = s2.sub(&s1);

    if h.is_zero() {
        return if r.is_zero() {
            p256_point_double(a)
        } else {
            P256JacobianPoint::infinity()
        };
    }

    let h_sq = h.sqr();
    let h_cu = h_sq.mul(&h);
    let u1h2 = u1.mul(&h_sq);

    // X3 = R^2 - H^3 - 2*U1*H^2
    let x3 = r.sqr().sub(&h_cu).sub(&u1h2).sub(&u1h2);

    // Y3 = R*(U1*H^2 - X3) - S1*H^3
    let y3 = r.mul(&u1h2.sub(&x3)).sub(&s1.mul(&h_cu));

    // Z3 = H * Z1 * Z2
    let z3 = h.mul(&a.z).mul(&b.z);

    P256JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Scalar multiplication using w=4 fixed-window method: R = k * P.
pub(crate) fn p256_scalar_mul(k: &BigNum, point: &P256JacobianPoint) -> P256JacobianPoint {
    if k.is_zero() || point.is_infinity() {
        return P256JacobianPoint::infinity();
    }

    // Precompute table[0..16] = [O, P, 2P, ..., 15P]
    let mut table = [P256JacobianPoint::infinity(); 16];
    table[1] = *point;
    table[2] = p256_point_double(point);
    for i in 3..16usize {
        table[i] = p256_point_add(&table[i - 1], point);
    }

    let bits = k.bit_len();
    let num_windows = bits.div_ceil(4);
    let mut result = P256JacobianPoint::infinity();

    for win_idx in (0..num_windows).rev() {
        // Double 4 times
        for _ in 0..4 {
            result = p256_point_double(&result);
        }

        // Get 4-bit window value (bits at base+3..base)
        let base = win_idx * 4;
        let mut w = 0usize;
        for j in 0..4 {
            let bit_pos = base + j;
            if bit_pos < bits && k.get_bit(bit_pos) != 0 {
                w |= 1 << j;
            }
        }

        if w != 0 {
            result = p256_point_add(&result, &table[w]);
        }
    }

    result
}

/// Scalar multiplication with base point: R = k * G.
pub(crate) fn p256_scalar_mul_base(k: &BigNum) -> P256JacobianPoint {
    let gx = P256FieldElement::from_bytes(&P256_GX);
    let gy = P256FieldElement::from_bytes(&P256_GY);
    let g = P256JacobianPoint::from_affine(&gx, &gy);
    p256_scalar_mul(k, &g)
}

/// Combined scalar multiplication (Shamir's trick): R = k1*G + k2*Q.
pub(crate) fn p256_scalar_mul_add(
    k1: &BigNum,
    k2: &BigNum,
    q: &P256JacobianPoint,
) -> P256JacobianPoint {
    if k1.is_zero() && k2.is_zero() {
        return P256JacobianPoint::infinity();
    }

    let gx = P256FieldElement::from_bytes(&P256_GX);
    let gy = P256FieldElement::from_bytes(&P256_GY);
    let g = P256JacobianPoint::from_affine(&gx, &gy);

    if k1.is_zero() {
        return p256_scalar_mul(k2, q);
    }
    if k2.is_zero() {
        return p256_scalar_mul(k1, &g);
    }

    let g_plus_q = p256_point_add(&g, q);

    let bits1 = k1.bit_len();
    let bits2 = k2.bit_len();
    let max_bits = bits1.max(bits2);

    let mut result = P256JacobianPoint::infinity();

    for i in (0..max_bits).rev() {
        result = p256_point_double(&result);

        let b1 = i < bits1 && k1.get_bit(i) != 0;
        let b2 = i < bits2 && k2.get_bit(i) != 0;

        match (b1, b2) {
            (true, true) => result = p256_point_add(&result, &g_plus_q),
            (true, false) => result = p256_point_add(&result, &g),
            (false, true) => result = p256_point_add(&result, q),
            _ => {}
        }
    }

    result
}

/// Convert BigNum affine coordinates to a P256JacobianPoint.
pub(crate) fn bignum_to_p256_point(
    x: &BigNum,
    y: &BigNum,
) -> Result<P256JacobianPoint, CryptoError> {
    let x_vec = x.to_bytes_be_padded(32)?;
    let y_vec = y.to_bytes_be_padded(32)?;
    let x_arr: &[u8; 32] = x_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidArg)?;
    let y_arr: &[u8; 32] = y_vec
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidArg)?;
    let x_fe = P256FieldElement::from_bytes(x_arr);
    let y_fe = P256FieldElement::from_bytes(y_arr);
    Ok(P256JacobianPoint::from_affine(&x_fe, &y_fe))
}

/// Convert a P256JacobianPoint back to affine BigNum coordinates.
///
/// Returns `Ok(None)` for the point at infinity.
pub(crate) fn p256_point_to_affine(
    point: &P256JacobianPoint,
) -> Result<Option<(BigNum, BigNum)>, CryptoError> {
    match point.to_affine() {
        Some((x_fe, y_fe)) => {
            let x = BigNum::from_bytes_be(&x_fe.to_bytes());
            let y = BigNum::from_bytes_be(&y_fe.to_bytes());
            Ok(Some((x, y)))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::curves::get_curve_params;
    use crate::ecc::point as generic;
    use hitls_types::EccCurveId;

    fn p256_generator() -> P256JacobianPoint {
        let gx = P256FieldElement::from_bytes(&P256_GX);
        let gy = P256FieldElement::from_bytes(&P256_GY);
        P256JacobianPoint::from_affine(&gx, &gy)
    }

    #[test]
    fn test_infinity_is_infinity() {
        assert!(P256JacobianPoint::infinity().is_infinity());
    }

    #[test]
    fn test_generator_not_infinity() {
        assert!(!p256_generator().is_infinity());
    }

    #[test]
    fn test_generator_affine_roundtrip() {
        let g = p256_generator();
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(x.to_bytes(), P256_GX);
        assert_eq!(y.to_bytes(), P256_GY);
    }

    #[test]
    fn test_double_equals_add() {
        let g = p256_generator();
        let two_g_dbl = p256_point_double(&g);
        let two_g_add = p256_point_add(&g, &g);

        let (x1, y1) = two_g_dbl.to_affine().unwrap();
        let (x2, y2) = two_g_add.to_affine().unwrap();
        assert_eq!(x1, x2);
        assert_eq!(y1, y2);
    }

    #[test]
    fn test_scalar_mul_base_one() {
        let one = BigNum::from_u64(1);
        let result = p256_scalar_mul_base(&one);
        let (x, y) = result.to_affine().unwrap();
        assert_eq!(x.to_bytes(), P256_GX);
        assert_eq!(y.to_bytes(), P256_GY);
    }

    #[test]
    fn test_scalar_mul_base_zero() {
        let zero = BigNum::zero();
        assert!(p256_scalar_mul_base(&zero).is_infinity());
    }

    #[test]
    fn test_scalar_mul_base_order_is_infinity() {
        let params = get_curve_params(EccCurveId::NistP256).unwrap();
        let result = p256_scalar_mul_base(&params.n);
        assert!(result.is_infinity());
    }

    #[test]
    fn test_scalar_mul_base_2g_matches_generic() {
        let params = get_curve_params(EccCurveId::NistP256).unwrap();
        let two = BigNum::from_u64(2);

        // P-256 specialized path
        let p256_result = p256_scalar_mul_base(&two);
        let (px, py) = p256_result.to_affine().unwrap();

        // Generic BigNum path
        let g = generic::JacobianPoint::from_affine(&params.gx, &params.gy);
        let gen_result = generic::scalar_mul(&two, &g, &params).unwrap();
        let (gx, gy) = gen_result.to_affine(&params.p).unwrap().unwrap();

        assert_eq!(
            BigNum::from_bytes_be(&px.to_bytes()),
            gx,
            "2G x-coordinates differ"
        );
        assert_eq!(
            BigNum::from_bytes_be(&py.to_bytes()),
            gy,
            "2G y-coordinates differ"
        );
    }

    #[test]
    fn test_scalar_mul_base_7g_matches_generic() {
        let params = get_curve_params(EccCurveId::NistP256).unwrap();
        let k = BigNum::from_u64(7);

        let p256_result = p256_scalar_mul_base(&k);
        let (px, py) = p256_result.to_affine().unwrap();

        let g = generic::JacobianPoint::from_affine(&params.gx, &params.gy);
        let gen_result = generic::scalar_mul(&k, &g, &params).unwrap();
        let (gx, gy) = gen_result.to_affine(&params.p).unwrap().unwrap();

        assert_eq!(BigNum::from_bytes_be(&px.to_bytes()), gx);
        assert_eq!(BigNum::from_bytes_be(&py.to_bytes()), gy);
    }

    #[test]
    fn test_scalar_mul_add_consistency() {
        let params = get_curve_params(EccCurveId::NistP256).unwrap();
        let k1 = BigNum::from_u64(3);
        let k2 = BigNum::from_u64(5);

        // Q = 2G
        let q = p256_point_double(&p256_generator());

        // Combined: k1*G + k2*Q
        let combined = p256_scalar_mul_add(&k1, &k2, &q);
        let (cx, cy) = combined.to_affine().unwrap();

        // Separate: k1*G + k2*Q
        let part1 = p256_scalar_mul_base(&k1);
        let part2 = p256_scalar_mul(&k2, &q);
        let separate = p256_point_add(&part1, &part2);
        let (sx, sy) = separate.to_affine().unwrap();

        assert_eq!(cx, sx);
        assert_eq!(cy, sy);
    }

    #[test]
    fn test_scalar_mul_add_matches_generic() {
        let params = get_curve_params(EccCurveId::NistP256).unwrap();
        let k1 = BigNum::from_u64(3);
        let k2 = BigNum::from_u64(5);

        // Q = 2G (as P256JacobianPoint)
        let q_p256 = p256_point_double(&p256_generator());

        // P-256 fast path
        let p256_result = p256_scalar_mul_add(&k1, &k2, &q_p256);
        let (px, py) = p256_result.to_affine().unwrap();

        // Generic BigNum path
        let g = generic::JacobianPoint::from_affine(&params.gx, &params.gy);
        let q_gen = generic::point_double(
            &generic::JacobianPoint::from_affine(&params.gx, &params.gy),
            &params,
        )
        .unwrap();
        let gen_result = generic::scalar_mul_add(&k1, &g, &k2, &q_gen, &params).unwrap();
        let (gx, gy) = gen_result.to_affine(&params.p).unwrap().unwrap();

        assert_eq!(BigNum::from_bytes_be(&px.to_bytes()), gx);
        assert_eq!(BigNum::from_bytes_be(&py.to_bytes()), gy);
    }

    #[test]
    fn test_bignum_conversion_roundtrip() {
        let params = get_curve_params(EccCurveId::NistP256).unwrap();
        let pt = bignum_to_p256_point(&params.gx, &params.gy).unwrap();
        let (x, y) = p256_point_to_affine(&pt).unwrap().unwrap();
        assert_eq!(x, params.gx);
        assert_eq!(y, params.gy);
    }

    #[test]
    fn test_point_add_identity() {
        let g = p256_generator();
        let inf = P256JacobianPoint::infinity();

        // G + O = G
        let r1 = p256_point_add(&g, &inf);
        let (x1, y1) = r1.to_affine().unwrap();
        assert_eq!(x1.to_bytes(), P256_GX);
        assert_eq!(y1.to_bytes(), P256_GY);

        // O + G = G
        let r2 = p256_point_add(&inf, &g);
        let (x2, y2) = r2.to_affine().unwrap();
        assert_eq!(x2.to_bytes(), P256_GX);
        assert_eq!(y2.to_bytes(), P256_GY);
    }

    #[test]
    fn test_add_inverse_is_infinity() {
        // G + (-G) = O
        // -G has y-coordinate negated: p - gy
        let p_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let p_fe = P256FieldElement::from_bytes(&p_bytes);
        let gx = P256FieldElement::from_bytes(&P256_GX);
        let gy = P256FieldElement::from_bytes(&P256_GY);
        let neg_gy = p_fe.sub(&gy);

        let g = P256JacobianPoint::from_affine(&gx, &gy);
        let neg_g = P256JacobianPoint::from_affine(&gx, &neg_gy);

        let result = p256_point_add(&g, &neg_g);
        assert!(result.is_infinity());
    }
}
