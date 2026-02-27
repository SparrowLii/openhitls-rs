#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input layout: 65B point + 1B msg_len + msg + rest=DER sig
    // Minimum: 65 + 1 + 0 + 1 = 67 bytes
    if data.len() < 67 {
        return;
    }

    let point = &data[..65];
    let msg_len = (data[65] as usize) % 128;
    let rest = &data[66..];

    if rest.len() < msg_len + 1 {
        return;
    }

    let msg = &rest[..msg_len];
    let sig = &rest[msg_len..];

    let kp = match hitls_crypto::sm2::Sm2KeyPair::from_public_key(point) {
        Ok(k) => k,
        Err(_) => return,
    };

    let _ = kp.verify(msg, sig);
});
