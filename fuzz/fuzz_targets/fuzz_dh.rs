#![no_main]
use hitls_types::DhParamId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Input: [group_sel(1B)]
    if data.is_empty() {
        return;
    }

    // Use smallest groups for fuzz speed
    let group_id = match data[0] % 2 {
        0 => DhParamId::Rfc2409_768,
        _ => DhParamId::Rfc2409_1024,
    };

    let params = match hitls_crypto::dh::DhParams::from_group(group_id) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Generate two key pairs
    let kp_a = match hitls_crypto::dh::DhKeyPair::generate(&params) {
        Ok(k) => k,
        Err(_) => return,
    };
    let kp_b = match hitls_crypto::dh::DhKeyPair::generate(&params) {
        Ok(k) => k,
        Err(_) => return,
    };

    let pub_a = match kp_a.public_key_bytes(&params) {
        Ok(p) => p,
        Err(_) => return,
    };
    let pub_b = match kp_b.public_key_bytes(&params) {
        Ok(p) => p,
        Err(_) => return,
    };

    // DH commutativity: dh(a, pub_b) == dh(b, pub_a)
    let ss_ab = match kp_a.compute_shared_secret(&params, &pub_b) {
        Ok(s) => s,
        Err(_) => return,
    };
    let ss_ba = match kp_b.compute_shared_secret(&params, &pub_a) {
        Ok(s) => s,
        Err(_) => return,
    };

    assert_eq!(ss_ab, ss_ba, "DH shared secret must be commutative");
});
