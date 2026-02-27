#![no_main]
use libfuzzer_sys::fuzz_target;

/// Simulate feeding a sequence of TLS 1.3 handshake messages through the codec.
/// Each chunk is prefixed with a 1-byte HandshakeType selector and 2-byte length,
/// then dispatched to the appropriate decoder. This exercises message sequencing
/// and interleaving that a real state machine would encounter.
fuzz_target!(|data: &[u8]| {
    // Need at least 3 bytes per chunk (1B type + 2B length)
    if data.len() < 3 {
        return;
    }

    let mut offset = 0;
    let mut msg_count = 0;

    // Process up to 16 messages from the fuzz input
    while offset + 3 <= data.len() && msg_count < 16 {
        let msg_type = data[offset];
        let chunk_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        // Cap chunk length to remaining data
        let actual_len = chunk_len.min(data.len() - offset);
        let body = &data[offset..offset + actual_len];
        offset += actual_len;

        // First, try parsing as a complete TLS record (5-byte header + fragment)
        if body.len() >= 5 {
            let record_bytes = body;
            // Try to parse as a TLS record header
            let layer = hitls_tls::record::RecordLayer::new();
            let _ = layer.parse_record(record_bytes);
        }

        // Then dispatch as a handshake message based on type selector
        match msg_type % 12 {
            0 => { let _ = hitls_tls::handshake::codec::decode_client_hello(body); }
            1 => { let _ = hitls_tls::handshake::codec::decode_server_hello(body); }
            2 => { let _ = hitls_tls::handshake::codec::decode_encrypted_extensions(body); }
            3 => { let _ = hitls_tls::handshake::codec::decode_certificate(body); }
            4 => { let _ = hitls_tls::handshake::codec::decode_certificate_verify(body); }
            5 => { let _ = hitls_tls::handshake::codec::decode_finished(body, 32); }
            6 => { let _ = hitls_tls::handshake::codec::decode_finished(body, 48); }
            7 => { let _ = hitls_tls::handshake::codec::decode_key_update(body); }
            8 => { let _ = hitls_tls::handshake::codec::decode_new_session_ticket(body); }
            9 => { let _ = hitls_tls::handshake::codec::decode_certificate_request(body); }
            10 => { let _ = hitls_tls::handshake::codec::decode_compressed_certificate(body); }
            11 => {
                // Parse as handshake header, then decode the body
                if let Ok((_hs_type, hs_body, _consumed)) =
                    hitls_tls::handshake::codec::parse_handshake_header(body)
                {
                    let _ = hitls_tls::handshake::codec::decode_server_hello(hs_body);
                }
            }
            _ => {}
        }

        msg_count += 1;
    }
});
