#![no_main]
use libfuzzer_sys::fuzz_target;

/// Simulate feeding a sequence of TLS 1.2 handshake messages through the codec.
/// Each chunk is prefixed with a 1-byte HandshakeType selector and 2-byte length,
/// then dispatched to the appropriate decoder. This exercises message sequencing
/// and interleaving that a real TLS 1.2 state machine would encounter.
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

        // First, try parsing as a TLS record
        if body.len() >= 5 {
            let layer = hitls_tls::record::RecordLayer::new();
            let _ = layer.parse_record(body);
        }

        // Dispatch as a TLS 1.2 handshake message based on type selector.
        // Mix in shared codecs (ClientHello/ServerHello from TLS 1.3 codec)
        // to simulate a full TLS 1.2 handshake sequence.
        match msg_type % 16 {
            // Shared messages (ClientHello/ServerHello use same wire format)
            0 => { let _ = hitls_tls::handshake::codec::decode_client_hello(body); }
            1 => { let _ = hitls_tls::handshake::codec::decode_server_hello(body); }
            // TLS 1.2-specific messages
            2 => { let _ = hitls_tls::handshake::codec12::decode_certificate12(body); }
            3 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange(body); }
            4 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange_dhe(body); }
            5 => { let _ = hitls_tls::handshake::codec12::decode_certificate_request12(body); }
            6 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange(body); }
            7 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange_rsa(body); }
            8 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange_dhe(body); }
            9 => { let _ = hitls_tls::handshake::codec12::decode_certificate_verify12(body); }
            10 => { let _ = hitls_tls::handshake::codec12::decode_finished12(body); }
            11 => { let _ = hitls_tls::handshake::codec12::decode_new_session_ticket12(body); }
            12 => { let _ = hitls_tls::handshake::codec12::decode_certificate_status12(body); }
            // PSK variants
            13 => { let _ = hitls_tls::handshake::codec12::decode_server_key_exchange_psk_hint(body); }
            14 => { let _ = hitls_tls::handshake::codec12::decode_client_key_exchange_psk(body); }
            15 => {
                // Parse handshake header first, then try to decode body
                if let Ok((_hs_type, hs_body, _consumed)) =
                    hitls_tls::handshake::codec::parse_handshake_header(body)
                {
                    let _ = hitls_tls::handshake::codec12::decode_server_key_exchange(hs_body);
                }
            }
            _ => {}
        }

        msg_count += 1;
    }
});
