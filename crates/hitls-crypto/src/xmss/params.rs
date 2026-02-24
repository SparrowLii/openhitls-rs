//! XMSS parameter sets (RFC 8391, single-tree only).
//!
//! All parameter sets use n=32, W=16, wots_len=67.

use hitls_types::XmssParamId;

/// XMSS parameter set.
pub(crate) struct XmssParams {
    pub n: usize,         // Hash output length (bytes), always 32
    pub h: usize,         // Tree height (10, 16, or 20)
    pub wots_len: usize,  // WOTS+ chain count (len_1 + len_2 = 64 + 3 = 67)
    pub sig_bytes: usize, // Total signature size = 4 + n + (wots_len + h) * n
}

/// Compute OID for the parameter set (RFC 8391 Section 5.3).
pub(crate) fn oid(param_id: XmssParamId) -> u32 {
    match param_id {
        XmssParamId::Sha2_10_256 => 0x00000001,
        XmssParamId::Sha2_16_256 => 0x00000002,
        XmssParamId::Sha2_20_256 => 0x00000003,
        XmssParamId::Shake128_10_256 => 0x00000007,
        XmssParamId::Shake128_16_256 => 0x00000008,
        XmssParamId::Shake128_20_256 => 0x00000009,
        XmssParamId::Shake256_10_256 => 0x0000000a,
        XmssParamId::Shake256_16_256 => 0x0000000b,
        XmssParamId::Shake256_20_256 => 0x0000000c,
    }
}

static PARAMS: [XmssParams; 9] = [
    // SHA2_10_256
    XmssParams {
        n: 32,
        h: 10,
        wots_len: 67,
        sig_bytes: 2500,
    },
    // SHA2_16_256
    XmssParams {
        n: 32,
        h: 16,
        wots_len: 67,
        sig_bytes: 2692,
    },
    // SHA2_20_256
    XmssParams {
        n: 32,
        h: 20,
        wots_len: 67,
        sig_bytes: 2820,
    },
    // SHAKE128_10_256
    XmssParams {
        n: 32,
        h: 10,
        wots_len: 67,
        sig_bytes: 2500,
    },
    // SHAKE128_16_256
    XmssParams {
        n: 32,
        h: 16,
        wots_len: 67,
        sig_bytes: 2692,
    },
    // SHAKE128_20_256
    XmssParams {
        n: 32,
        h: 20,
        wots_len: 67,
        sig_bytes: 2820,
    },
    // SHAKE256_10_256
    XmssParams {
        n: 32,
        h: 10,
        wots_len: 67,
        sig_bytes: 2500,
    },
    // SHAKE256_16_256
    XmssParams {
        n: 32,
        h: 16,
        wots_len: 67,
        sig_bytes: 2692,
    },
    // SHAKE256_20_256
    XmssParams {
        n: 32,
        h: 20,
        wots_len: 67,
        sig_bytes: 2820,
    },
];

pub(crate) fn get_params(param_id: XmssParamId) -> &'static XmssParams {
    let idx = match param_id {
        XmssParamId::Sha2_10_256 => 0,
        XmssParamId::Sha2_16_256 => 1,
        XmssParamId::Sha2_20_256 => 2,
        XmssParamId::Shake128_10_256 => 3,
        XmssParamId::Shake128_16_256 => 4,
        XmssParamId::Shake128_20_256 => 5,
        XmssParamId::Shake256_10_256 => 6,
        XmssParamId::Shake256_16_256 => 7,
        XmssParamId::Shake256_20_256 => 8,
    };
    &PARAMS[idx]
}

/// Hash mode for XMSS.
#[derive(Clone, Copy)]
pub(crate) enum XmssHashMode {
    Sha256,
    Shake128,
    Shake256,
}

pub(crate) fn hash_mode(param_id: XmssParamId) -> XmssHashMode {
    match param_id {
        XmssParamId::Sha2_10_256 | XmssParamId::Sha2_16_256 | XmssParamId::Sha2_20_256 => {
            XmssHashMode::Sha256
        }
        XmssParamId::Shake128_10_256
        | XmssParamId::Shake128_16_256
        | XmssParamId::Shake128_20_256 => XmssHashMode::Shake128,
        XmssParamId::Shake256_10_256
        | XmssParamId::Shake256_16_256
        | XmssParamId::Shake256_20_256 => XmssHashMode::Shake256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hitls_types::XmssParamId;

    const ALL_IDS: [XmssParamId; 9] = [
        XmssParamId::Sha2_10_256,
        XmssParamId::Sha2_16_256,
        XmssParamId::Sha2_20_256,
        XmssParamId::Shake128_10_256,
        XmssParamId::Shake128_16_256,
        XmssParamId::Shake128_20_256,
        XmssParamId::Shake256_10_256,
        XmssParamId::Shake256_16_256,
        XmssParamId::Shake256_20_256,
    ];

    #[test]
    fn test_xmss_params_sig_bytes_and_oid() {
        for id in &ALL_IDS {
            let p = get_params(*id);
            // All sets: n=32, wots_len=67
            assert_eq!(p.n, 32);
            assert_eq!(p.wots_len, 67);
            // sig_bytes = 4 + n + (wots_len + h) * n
            let expected = 4 + p.n + (p.wots_len + p.h) * p.n;
            assert_eq!(p.sig_bytes, expected, "sig_bytes mismatch for h={}", p.h);
        }

        // Check specific OID values from RFC 8391
        assert_eq!(oid(XmssParamId::Sha2_10_256), 0x00000001);
        assert_eq!(oid(XmssParamId::Sha2_16_256), 0x00000002);
        assert_eq!(oid(XmssParamId::Sha2_20_256), 0x00000003);
        assert_eq!(oid(XmssParamId::Shake128_10_256), 0x00000007);
        assert_eq!(oid(XmssParamId::Shake256_10_256), 0x0000000a);
    }

    #[test]
    fn test_xmss_all_heights_valid() {
        for id in &ALL_IDS {
            let p = get_params(*id);
            assert!(
                p.h == 10 || p.h == 16 || p.h == 20,
                "unexpected h={} for XMSS",
                p.h
            );
        }
    }

    #[test]
    fn test_xmss_oid_uniqueness() {
        let oids: Vec<u32> = ALL_IDS.iter().map(|id| oid(*id)).collect();
        for i in 0..oids.len() {
            for j in (i + 1)..oids.len() {
                assert_ne!(oids[i], oids[j], "duplicate OID at indices {} and {}", i, j);
            }
        }
    }

    #[test]
    fn test_xmss_hash_mode_consistency() {
        // SHA-2 variants → Sha256 mode
        for id in [
            XmssParamId::Sha2_10_256,
            XmssParamId::Sha2_16_256,
            XmssParamId::Sha2_20_256,
        ] {
            assert!(matches!(hash_mode(id), XmssHashMode::Sha256));
        }
        // SHAKE128 variants → Shake128 mode
        for id in [
            XmssParamId::Shake128_10_256,
            XmssParamId::Shake128_16_256,
            XmssParamId::Shake128_20_256,
        ] {
            assert!(matches!(hash_mode(id), XmssHashMode::Shake128));
        }
        // SHAKE256 variants → Shake256 mode
        for id in [
            XmssParamId::Shake256_10_256,
            XmssParamId::Shake256_16_256,
            XmssParamId::Shake256_20_256,
        ] {
            assert!(matches!(hash_mode(id), XmssHashMode::Shake256));
        }
    }

    #[test]
    fn test_xmss_same_height_same_sig_size() {
        // Same h → same sig_bytes regardless of hash mode
        let h10 = [
            XmssParamId::Sha2_10_256,
            XmssParamId::Shake128_10_256,
            XmssParamId::Shake256_10_256,
        ];
        let h16 = [
            XmssParamId::Sha2_16_256,
            XmssParamId::Shake128_16_256,
            XmssParamId::Shake256_16_256,
        ];
        let h20 = [
            XmssParamId::Sha2_20_256,
            XmssParamId::Shake128_20_256,
            XmssParamId::Shake256_20_256,
        ];
        for group in [&h10[..], &h16[..], &h20[..]] {
            let first = get_params(group[0]).sig_bytes;
            for id in &group[1..] {
                assert_eq!(get_params(*id).sig_bytes, first);
            }
        }
    }

    #[test]
    fn test_xmss_sig_bytes_monotonic_with_height() {
        let s10 = get_params(XmssParamId::Sha2_10_256).sig_bytes;
        let s16 = get_params(XmssParamId::Sha2_16_256).sig_bytes;
        let s20 = get_params(XmssParamId::Sha2_20_256).sig_bytes;
        assert!(
            s10 < s16,
            "h=10 sig ({}) should be < h=16 sig ({})",
            s10,
            s16
        );
        assert!(
            s16 < s20,
            "h=16 sig ({}) should be < h=20 sig ({})",
            s16,
            s20
        );
    }
}
