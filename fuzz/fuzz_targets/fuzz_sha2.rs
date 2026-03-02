#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [alg_sel(1B), split_pos(1B), rest...]
    if data.len() < 3 {
        return;
    }

    let alg_sel = data[0];
    let split_byte = data[1] as usize;
    let rest = &data[2..];
    let split = split_byte % (rest.len() + 1);

    match alg_sel % 3 {
        0 => {
            // SHA-256: one-shot vs incremental
            let one_shot = hitls_crypto::sha2::Sha256::digest(rest).unwrap();
            let mut h = hitls_crypto::sha2::Sha256::new();
            h.update(&rest[..split]).unwrap();
            h.update(&rest[split..]).unwrap();
            let incremental = h.finish().unwrap();
            assert_eq!(one_shot, incremental, "SHA-256 incremental must match one-shot");
        }
        1 => {
            // SHA-384: one-shot vs incremental
            let one_shot = hitls_crypto::sha2::Sha384::digest(rest).unwrap();
            let mut h = hitls_crypto::sha2::Sha384::new();
            h.update(&rest[..split]).unwrap();
            h.update(&rest[split..]).unwrap();
            let incremental = h.finish().unwrap();
            assert_eq!(one_shot, incremental, "SHA-384 incremental must match one-shot");
        }
        _ => {
            // SHA-512: one-shot vs incremental
            let one_shot = hitls_crypto::sha2::Sha512::digest(rest).unwrap();
            let mut h = hitls_crypto::sha2::Sha512::new();
            h.update(&rest[..split]).unwrap();
            h.update(&rest[split..]).unwrap();
            let incremental = h.finish().unwrap();
            assert_eq!(one_shot, incremental, "SHA-512 incremental must match one-shot");
        }
    }
});
