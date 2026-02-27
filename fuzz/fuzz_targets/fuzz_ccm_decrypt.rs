#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input layout: 16B key + 1B nonce_sel + 1B tag_sel + 1B aad_len + rest
    // Minimum: 16 + 1 + 1 + 1 + 1 = 20 bytes
    if data.len() < 20 {
        return;
    }

    let key = &data[..16];
    let nonce_sel = data[16];
    let tag_sel = data[17];
    let aad_len = (data[18] as usize) % 32;
    let rest = &data[19..];

    // CCM nonce must be 7..=13 bytes
    let nonce_len = 7 + (nonce_sel as usize % 7); // 7..13
    if rest.len() < nonce_len + aad_len + 1 {
        return;
    }

    let nonce = &rest[..nonce_len];
    let aad = &rest[nonce_len..nonce_len + aad_len];
    let ct = &rest[nonce_len + aad_len..];

    // CCM tag must be 4, 6, 8, 10, 12, 14, or 16 bytes
    let tag_lengths = [4, 6, 8, 10, 12, 14, 16];
    let tag_len = tag_lengths[(tag_sel as usize) % tag_lengths.len()];

    let _ = hitls_crypto::modes::ccm::ccm_decrypt(key, nonce, aad, ct, tag_len);
});
