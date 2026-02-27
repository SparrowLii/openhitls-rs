#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input layout: 256B n + 3B e + 32B digest + rest=signature
    // Minimum: 256 + 3 + 32 + 1 = 292 bytes
    if data.len() < 292 {
        return;
    }

    let n = &data[..256];
    let e = &data[256..259];
    let digest = &data[259..291];
    let sig = &data[291..];

    let pub_key = match hitls_crypto::rsa::RsaPublicKey::new(n, e) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Try PKCS#1v15 verify
    let _ = pub_key.verify(hitls_crypto::rsa::RsaPadding::Pkcs1v15Sign, digest, sig);

    // Try PSS verify
    let _ = pub_key.verify(hitls_crypto::rsa::RsaPadding::Pss, digest, sig);
});
