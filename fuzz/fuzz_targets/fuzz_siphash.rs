#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let key = &data[..16];
    let msg = &data[16..];

    // One-shot
    let h1 = match hitls_crypto::siphash::SipHash::hash(key, msg) {
        Ok(h) => h,
        Err(_) => return,
    };

    // Incremental
    let mut ctx = match hitls_crypto::siphash::SipHash::new(key) {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = ctx.update(msg);
    let h2 = match ctx.finish() {
        Ok(h) => h,
        Err(_) => return,
    };

    assert_eq!(h1, h2);
});
