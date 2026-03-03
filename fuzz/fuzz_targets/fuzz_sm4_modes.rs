#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [mode_sel(1B), key(16B), iv_or_nonce(16B), rest...]
    // Minimum: 1 + 16 + 16 = 33 bytes
    if data.len() < 33 {
        return;
    }

    let mode_sel = data[0];
    let key = &data[1..17];
    let iv = &data[17..33];
    let rest = &data[33..];

    match mode_sel % 3 {
        0 => {
            // SM4-CBC encrypt → decrypt roundtrip
            let ct = match hitls_crypto::modes::cbc::sm4_cbc_encrypt(key, iv, rest) {
                Ok(c) => c,
                Err(_) => return,
            };
            let pt = match hitls_crypto::modes::cbc::sm4_cbc_decrypt(key, iv, &ct) {
                Ok(p) => p,
                Err(_) => return,
            };
            assert_eq!(pt, rest, "SM4-CBC roundtrip must be lossless");
        }
        1 => {
            // SM4-GCM encrypt → decrypt roundtrip
            // Use first 12 bytes of iv as nonce
            let nonce = &iv[..12];
            let aad = if rest.len() > 4 { &rest[..4] } else { b"" as &[u8] };
            let plaintext = if rest.len() > 4 { &rest[4..] } else { rest };

            let ct = match hitls_crypto::modes::gcm::sm4_gcm_encrypt(key, nonce, aad, plaintext) {
                Ok(c) => c,
                Err(_) => return,
            };
            let pt =
                match hitls_crypto::modes::gcm::sm4_gcm_decrypt(key, nonce, aad, &ct) {
                    Ok(p) => p,
                    Err(_) => return,
                };
            assert_eq!(pt, plaintext, "SM4-GCM roundtrip must be lossless");
        }
        _ => {
            // SM4-GCM decrypt with fuzzed ciphertext — must not panic
            let nonce = &iv[..12];
            let _ = hitls_crypto::modes::gcm::sm4_gcm_decrypt(key, nonce, b"", rest);
        }
    }
});
