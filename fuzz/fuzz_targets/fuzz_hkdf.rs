#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input layout: 1B salt_len + 1B ikm_len + 1B info_len + 1B okm_len + bytes
    // Minimum: 4 bytes
    if data.len() < 4 {
        return;
    }

    let salt_len = (data[0] as usize) % 64;
    let ikm_len = (data[1] as usize) % 64;
    let info_len = (data[2] as usize) % 64;
    let okm_len = ((data[3] as usize) % 255) + 1; // 1..256

    let rest = &data[4..];
    if rest.len() < salt_len + ikm_len + info_len {
        return;
    }

    let salt = &rest[..salt_len];
    let ikm = &rest[salt_len..salt_len + ikm_len];
    let info = &rest[salt_len + ikm_len..salt_len + ikm_len + info_len];

    // One-shot derive
    let _ = hitls_crypto::hkdf::Hkdf::derive(salt, ikm, info, okm_len);

    // Two-step: extract then expand
    if let Ok(hkdf) = hitls_crypto::hkdf::Hkdf::new(salt, ikm) {
        let _ = hkdf.expand(info, okm_len);
    }
});
