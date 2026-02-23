//! Classic McEliece parameter sets.

use hitls_types::algorithm::McElieceParamId;

/// Parameters for a Classic McEliece instance.
#[derive(Debug, Clone, Copy)]
pub(crate) struct McElieceParams {
    pub m: usize,
    pub n: usize,
    pub t: usize,
    pub mt: usize,
    pub k: usize,
    pub n_bytes: usize,
    pub mt_bytes: usize,
    pub k_bytes: usize,
    pub private_key_bytes: usize,
    pub public_key_bytes: usize,
    pub cipher_bytes: usize,
    pub shared_key_bytes: usize,
    pub semi: bool,
    pub pc: bool,
}

pub(crate) const Q: usize = 8192;
pub(crate) const Q_1: u16 = 8191;
pub(crate) const L_BYTES: usize = 32;
pub(crate) const SIGMA1: usize = 16;
pub(crate) const SIGMA2: usize = 32;
pub(crate) const MU: usize = 32;
pub(crate) const NU: usize = 64;

pub(crate) const ALL_PARAM_IDS: [McElieceParamId; 12] = [
    McElieceParamId::McEliece6688128,
    McElieceParamId::McEliece6688128F,
    McElieceParamId::McEliece6688128Pc,
    McElieceParamId::McEliece6688128Pcf,
    McElieceParamId::McEliece6960119,
    McElieceParamId::McEliece6960119F,
    McElieceParamId::McEliece6960119Pc,
    McElieceParamId::McEliece6960119Pcf,
    McElieceParamId::McEliece8192128,
    McElieceParamId::McEliece8192128F,
    McElieceParamId::McEliece8192128Pc,
    McElieceParamId::McEliece8192128Pcf,
];

pub(crate) fn get_params(id: McElieceParamId) -> McElieceParams {
    use McElieceParamId::*;
    match id {
        McEliece6688128 => McElieceParams {
            m: 13,
            n: 6688,
            t: 128,
            mt: 1664,
            k: 5024,
            n_bytes: 836,
            mt_bytes: 208,
            k_bytes: 628,
            private_key_bytes: 13932,
            public_key_bytes: 1044992,
            cipher_bytes: 208,
            shared_key_bytes: 32,
            semi: false,
            pc: false,
        },
        McEliece6688128F => McElieceParams {
            m: 13,
            n: 6688,
            t: 128,
            mt: 1664,
            k: 5024,
            n_bytes: 836,
            mt_bytes: 208,
            k_bytes: 628,
            private_key_bytes: 13932,
            public_key_bytes: 1044992,
            cipher_bytes: 208,
            shared_key_bytes: 32,
            semi: true,
            pc: false,
        },
        McEliece6688128Pc => McElieceParams {
            m: 13,
            n: 6688,
            t: 128,
            mt: 1664,
            k: 5024,
            n_bytes: 836,
            mt_bytes: 208,
            k_bytes: 628,
            private_key_bytes: 13932,
            public_key_bytes: 1044992,
            cipher_bytes: 240,
            shared_key_bytes: 32,
            semi: false,
            pc: true,
        },
        McEliece6688128Pcf => McElieceParams {
            m: 13,
            n: 6688,
            t: 128,
            mt: 1664,
            k: 5024,
            n_bytes: 836,
            mt_bytes: 208,
            k_bytes: 628,
            private_key_bytes: 13932,
            public_key_bytes: 1044992,
            cipher_bytes: 240,
            shared_key_bytes: 32,
            semi: true,
            pc: true,
        },
        McEliece6960119 => McElieceParams {
            m: 13,
            n: 6960,
            t: 119,
            mt: 1547,
            k: 5413,
            n_bytes: 870,
            mt_bytes: 194,
            k_bytes: 677,
            private_key_bytes: 13948,
            public_key_bytes: 1047319,
            cipher_bytes: 194,
            shared_key_bytes: 32,
            semi: false,
            pc: false,
        },
        McEliece6960119F => McElieceParams {
            m: 13,
            n: 6960,
            t: 119,
            mt: 1547,
            k: 5413,
            n_bytes: 870,
            mt_bytes: 194,
            k_bytes: 677,
            private_key_bytes: 13948,
            public_key_bytes: 1047319,
            cipher_bytes: 194,
            shared_key_bytes: 32,
            semi: true,
            pc: false,
        },
        McEliece6960119Pc => McElieceParams {
            m: 13,
            n: 6960,
            t: 119,
            mt: 1547,
            k: 5413,
            n_bytes: 870,
            mt_bytes: 226,
            k_bytes: 677,
            private_key_bytes: 13948,
            public_key_bytes: 1047319,
            cipher_bytes: 226,
            shared_key_bytes: 32,
            semi: false,
            pc: true,
        },
        McEliece6960119Pcf => McElieceParams {
            m: 13,
            n: 6960,
            t: 119,
            mt: 1547,
            k: 5413,
            n_bytes: 870,
            mt_bytes: 226,
            k_bytes: 677,
            private_key_bytes: 13948,
            public_key_bytes: 1047319,
            cipher_bytes: 226,
            shared_key_bytes: 32,
            semi: true,
            pc: true,
        },
        McEliece8192128 => McElieceParams {
            m: 13,
            n: 8192,
            t: 128,
            mt: 1664,
            k: 6528,
            n_bytes: 1024,
            mt_bytes: 208,
            k_bytes: 816,
            private_key_bytes: 14120,
            public_key_bytes: 1357824,
            cipher_bytes: 208,
            shared_key_bytes: 32,
            semi: false,
            pc: false,
        },
        McEliece8192128F => McElieceParams {
            m: 13,
            n: 8192,
            t: 128,
            mt: 1664,
            k: 6528,
            n_bytes: 1024,
            mt_bytes: 208,
            k_bytes: 816,
            private_key_bytes: 14120,
            public_key_bytes: 1357824,
            cipher_bytes: 208,
            shared_key_bytes: 32,
            semi: true,
            pc: false,
        },
        McEliece8192128Pc => McElieceParams {
            m: 13,
            n: 8192,
            t: 128,
            mt: 1664,
            k: 6528,
            n_bytes: 1024,
            mt_bytes: 208,
            k_bytes: 816,
            private_key_bytes: 14120,
            public_key_bytes: 1357824,
            cipher_bytes: 240,
            shared_key_bytes: 32,
            semi: false,
            pc: true,
        },
        McEliece8192128Pcf => McElieceParams {
            m: 13,
            n: 8192,
            t: 128,
            mt: 1664,
            k: 6528,
            n_bytes: 1024,
            mt_bytes: 208,
            k_bytes: 816,
            private_key_bytes: 14120,
            public_key_bytes: 1357824,
            cipher_bytes: 240,
            shared_key_bytes: 32,
            semi: true,
            pc: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mceliece_params_invariants() {
        for id in &ALL_PARAM_IDS {
            let p = get_params(*id);

            // mt == m * t
            assert_eq!(p.mt, p.m * p.t, "mt != m*t for n={}", p.n);

            // k == n - mt
            assert_eq!(p.k, p.n - p.mt, "k != n-mt for n={}", p.n);

            // n_bytes == ceil(n/8)
            assert_eq!(p.n_bytes, p.n.div_ceil(8), "n_bytes mismatch for n={}", p.n);

            // shared_key_bytes always 32
            assert_eq!(p.shared_key_bytes, 32);

            // m is always 13
            assert_eq!(p.m, 13);

            // pc variants: cipher_bytes == ceil(mt/8) + 32
            // non-pc variants: cipher_bytes == ceil(mt/8)
            let base_cipher = p.mt.div_ceil(8);
            if p.pc {
                assert_eq!(
                    p.cipher_bytes,
                    base_cipher + 32,
                    "pc cipher mismatch for n={}",
                    p.n
                );
            } else {
                assert_eq!(p.cipher_bytes, base_cipher, "cipher mismatch for n={}", p.n);
            }
        }
    }
}
