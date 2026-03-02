#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: key(16B) + block(16B) = 32 bytes minimum
    if data.len() < 32 {
        return;
    }

    let key = &data[..16];
    let block_data = &data[16..32];

    let cipher = match hitls_crypto::sm4::Sm4Key::new(key) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Encrypt → decrypt roundtrip
    let mut buf = [0u8; 16];
    buf.copy_from_slice(block_data);
    let original = buf;

    if cipher.encrypt_block(&mut buf).is_err() {
        return;
    }
    if cipher.decrypt_block(&mut buf).is_err() {
        return;
    }

    assert_eq!(buf, original, "SM4 block roundtrip must be lossless");
});
