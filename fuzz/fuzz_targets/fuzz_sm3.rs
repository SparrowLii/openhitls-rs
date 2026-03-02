#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [split_pos(1B), rest...]
    if data.len() < 2 {
        return;
    }

    let split_byte = data[0] as usize;
    let rest = &data[1..];
    let split = split_byte % (rest.len() + 1);

    // SM3: one-shot vs incremental
    let one_shot = hitls_crypto::sm3::Sm3::digest(rest).unwrap();

    let mut h = hitls_crypto::sm3::Sm3::new();
    h.update(&rest[..split]).unwrap();
    h.update(&rest[split..]).unwrap();
    let incremental = h.finish().unwrap();

    assert_eq!(one_shot, incremental, "SM3 incremental must match one-shot");
});
