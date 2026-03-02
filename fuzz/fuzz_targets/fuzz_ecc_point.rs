#![no_main]
use hitls_types::EccCurveId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [curve_sel(1B)]
    if data.is_empty() {
        return;
    }

    let curve = match data[0] % 3 {
        0 => EccCurveId::NistP256,
        1 => EccCurveId::NistP384,
        _ => EccCurveId::NistP521,
    };

    // Generate a key pair and verify public key round-trip via ECDH
    let kp = match hitls_crypto::ecdh::EcdhKeyPair::generate(curve) {
        Ok(k) => k,
        Err(_) => return,
    };

    let pub_bytes = match kp.public_key_bytes() {
        Ok(p) => p,
        Err(_) => return,
    };

    // Public key bytes should be non-empty and represent a valid point
    assert!(!pub_bytes.is_empty(), "public key bytes should not be empty");

    // Self-ECDH: compute shared secret with self (should succeed, not panic)
    let _ = kp.compute_shared_secret(&pub_bytes);

    // Generate a second key pair and verify commutativity
    let kp2 = match hitls_crypto::ecdh::EcdhKeyPair::generate(curve) {
        Ok(k) => k,
        Err(_) => return,
    };

    let pub2 = match kp2.public_key_bytes() {
        Ok(p) => p,
        Err(_) => return,
    };

    let ss_ab = match kp.compute_shared_secret(&pub2) {
        Ok(s) => s,
        Err(_) => return,
    };
    let ss_ba = match kp2.compute_shared_secret(&pub_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    assert_eq!(ss_ab, ss_ba, "ECC DH shared secret must be commutative");
});
