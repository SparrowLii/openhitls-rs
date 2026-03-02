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

    match alg_sel % 4 {
        0 => {
            // SHA3-256: one-shot vs incremental
            let one_shot = hitls_crypto::sha3::Sha3_256::digest(rest).unwrap();
            let mut h = hitls_crypto::sha3::Sha3_256::new();
            h.update(&rest[..split]).unwrap();
            h.update(&rest[split..]).unwrap();
            let incremental = h.finish().unwrap();
            assert_eq!(one_shot, incremental, "SHA3-256 incremental must match one-shot");
        }
        1 => {
            // SHA3-512: one-shot vs incremental
            let one_shot = hitls_crypto::sha3::Sha3_512::digest(rest).unwrap();
            let mut h = hitls_crypto::sha3::Sha3_512::new();
            h.update(&rest[..split]).unwrap();
            h.update(&rest[split..]).unwrap();
            let incremental = h.finish().unwrap();
            assert_eq!(one_shot, incremental, "SHA3-512 incremental must match one-shot");
        }
        2 => {
            // SHAKE-128: determinism check (squeeze 32 bytes twice)
            let mut s1 = hitls_crypto::sha3::Shake128::new();
            s1.update(rest).unwrap();
            let out1 = s1.squeeze(32).unwrap();

            let mut s2 = hitls_crypto::sha3::Shake128::new();
            s2.update(&rest[..split]).unwrap();
            s2.update(&rest[split..]).unwrap();
            let out2 = s2.squeeze(32).unwrap();

            assert_eq!(out1, out2, "SHAKE-128 incremental must match one-shot");
        }
        _ => {
            // SHAKE-256: determinism check (squeeze 64 bytes twice)
            let mut s1 = hitls_crypto::sha3::Shake256::new();
            s1.update(rest).unwrap();
            let out1 = s1.squeeze(64).unwrap();

            let mut s2 = hitls_crypto::sha3::Shake256::new();
            s2.update(&rest[..split]).unwrap();
            s2.update(&rest[split..]).unwrap();
            let out2 = s2.squeeze(64).unwrap();

            assert_eq!(out1, out2, "SHAKE-256 incremental must match one-shot");
        }
    }
});
