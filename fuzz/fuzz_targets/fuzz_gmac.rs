#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 28 {
        return; // need 16 key + 12 nonce
    }
    let key = &data[..16];
    let nonce = &data[16..28];
    let msg = &data[28..];

    let mut g1 = match hitls_crypto::gmac::Gmac::new(key, nonce) {
        Ok(g) => g,
        Err(_) => return,
    };

    // Compute tag
    let _ = g1.update(msg);
    let mut tag = [0u8; 16];
    let _ = g1.finish(&mut tag);

    // Verify determinism: same inputs → same tag
    let mut g2 = match hitls_crypto::gmac::Gmac::new(key, nonce) {
        Ok(g) => g,
        Err(_) => return,
    };
    let _ = g2.update(msg);
    let mut tag2 = [0u8; 16];
    let _ = g2.finish(&mut tag2);

    assert_eq!(tag, tag2);
});
