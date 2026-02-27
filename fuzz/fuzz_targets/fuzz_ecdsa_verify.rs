#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input layout: 1B curve_sel + 65B point + 32B digest + rest=DER sig
    // Minimum: 1 + 65 + 32 + 1 = 99 bytes
    if data.len() < 99 {
        return;
    }

    let curve_sel = data[0];
    let point = &data[1..66];
    let digest = &data[66..98];
    let sig = &data[98..];

    // Select curve based on first byte
    let curve = match curve_sel % 3 {
        0 => hitls_types::EccCurveId::NistP256,
        1 => hitls_types::EccCurveId::NistP384,
        _ => hitls_types::EccCurveId::NistP521,
    };

    let kp = match hitls_crypto::ecdsa::EcdsaKeyPair::from_public_key(curve, point) {
        Ok(k) => k,
        Err(_) => return,
    };

    let _ = kp.verify(digest, sig);
});
