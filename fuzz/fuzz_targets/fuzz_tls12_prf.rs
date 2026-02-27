#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input layout: 1B alg_sel + 1B sec_len + 1B lbl_len + 1B out_len + bytes
    // Minimum: 4 bytes
    if data.len() < 4 {
        return;
    }

    let alg_sel = data[0];
    let sec_len = (data[1] as usize) % 64;
    let lbl_len = (data[2] as usize) % 32;
    let out_len = ((data[3] as usize) % 255) + 1; // 1..256

    let rest = &data[4..];
    if rest.len() < sec_len + lbl_len {
        return;
    }

    let secret = &rest[..sec_len];
    let label_bytes = &rest[sec_len..sec_len + lbl_len];
    let seed = &rest[sec_len + lbl_len..];

    // Convert label bytes to UTF-8 string (best-effort)
    let label = match std::str::from_utf8(label_bytes) {
        Ok(s) => s,
        Err(_) => "master secret",
    };

    // Select hash algorithm
    let alg = match alg_sel % 3 {
        0 => hitls_tls::crypt::HashAlgId::Sha256,
        1 => hitls_tls::crypt::HashAlgId::Sha384,
        _ => hitls_tls::crypt::HashAlgId::Sha1,
    };

    let _ = hitls_tls::crypt::prf::prf(alg, secret, label, seed, out_len);
});
