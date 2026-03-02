#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let key = &data[..16];
    let msg = &data[16..];

    let mac = match hitls_crypto::cbc_mac::CbcMacSm4::new(key) {
        Ok(m) => m,
        Err(_) => return,
    };

    // One-shot
    let mut m1 = mac.clone();
    let _ = m1.update(msg);
    let mut tag1 = [0u8; 16];
    let _ = m1.finish(&mut tag1);

    // Incremental (byte-by-byte) — must produce same result
    let mut m2 = mac.clone();
    for &b in msg {
        let _ = m2.update(&[b]);
    }
    let mut tag2 = [0u8; 16];
    let _ = m2.finish(&mut tag2);

    assert_eq!(tag1, tag2);
});
