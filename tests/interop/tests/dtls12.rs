//! DTLS 1.2 handshake, data, anti-replay, and abbreviated handshake integration tests.

use hitls_integration_tests::*;

#[test]
fn test_dtls12_handshake_no_cookie() {
    use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
    use hitls_tls::TlsVersion;

    let (cc, sc) = make_dtls12_configs();
    let (client, server) = dtls12_handshake_in_memory(cc, sc, false).unwrap();
    assert_eq!(client.version(), Some(TlsVersion::Dtls12));
    assert_eq!(server.version(), Some(TlsVersion::Dtls12));
}

#[test]
fn test_dtls12_handshake_with_cookie() {
    use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
    use hitls_tls::TlsVersion;

    let (cc, sc) = make_dtls12_configs();
    let (client, server) = dtls12_handshake_in_memory(cc, sc, true).unwrap();
    assert_eq!(client.version(), Some(TlsVersion::Dtls12));
    assert_eq!(server.version(), Some(TlsVersion::Dtls12));
}

#[test]
fn test_dtls12_data_roundtrip() {
    use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;

    let (cc, sc) = make_dtls12_configs();
    let (mut client, mut server) = dtls12_handshake_in_memory(cc, sc, false).unwrap();

    // Client -> Server
    let datagram = client.seal_app_data(b"Hello from DTLS client").unwrap();
    let pt = server.open_app_data(&datagram).unwrap();
    assert_eq!(pt, b"Hello from DTLS client");

    // Server -> Client
    let datagram = server.seal_app_data(b"Hello from DTLS server").unwrap();
    let pt = client.open_app_data(&datagram).unwrap();
    assert_eq!(pt, b"Hello from DTLS server");
}

#[test]
fn test_dtls12_multiple_datagrams() {
    use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;

    let (cc, sc) = make_dtls12_configs();
    let (mut client, mut server) = dtls12_handshake_in_memory(cc, sc, false).unwrap();

    for i in 0..20u32 {
        let msg = format!("DTLS message #{i}");
        let dg = client.seal_app_data(msg.as_bytes()).unwrap();
        let pt = server.open_app_data(&dg).unwrap();
        assert_eq!(pt, msg.as_bytes());

        let reply = format!("DTLS reply #{i}");
        let dg = server.seal_app_data(reply.as_bytes()).unwrap();
        let pt = client.open_app_data(&dg).unwrap();
        assert_eq!(pt, reply.as_bytes());
    }
}

#[test]
fn test_dtls12_anti_replay() {
    use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;

    let (cc, sc) = make_dtls12_configs();
    let (mut client, mut server) = dtls12_handshake_in_memory(cc, sc, false).unwrap();

    let datagram = client.seal_app_data(b"replay me").unwrap();
    // First open succeeds
    let pt = server.open_app_data(&datagram).unwrap();
    assert_eq!(pt, b"replay me");
    // Second open (replay) should fail
    let result = server.open_app_data(&datagram);
    assert!(result.is_err(), "replayed datagram should be rejected");
}

/// DTLS 1.2: Full handshake followed by an abbreviated (session resumption) handshake.
#[test]
fn test_dtls12_integration_abbreviated_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::session::{InMemorySessionCache, SessionCache};
    use hitls_tls::{CipherSuite, TlsVersion};
    use std::sync::{Arc, Mutex};

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
    let server_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

    let make_client_config = |cache: Arc<Mutex<InMemorySessionCache>>| {
        TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .server_name("dtls.test.example")
            .session_cache(cache)
            .build()
    };

    let make_server_config = |cache: Arc<Mutex<InMemorySessionCache>>| {
        TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain.clone())
            .private_key(server_key.clone())
            .verify_peer(false)
            .session_cache(cache)
            .build()
    };

    // 1st connection: full handshake -> populates session caches
    let cc1 = make_client_config(client_cache.clone());
    let sc1 = make_server_config(server_cache.clone());
    let (client1, server1) = dtls12_handshake_in_memory(cc1, sc1, false).unwrap();
    assert_eq!(client1.version(), Some(TlsVersion::Dtls12));
    assert_eq!(server1.version(), Some(TlsVersion::Dtls12));

    // Verify session was cached on the client
    let session_stored = {
        let cache = client_cache.lock().unwrap();
        cache.get(b"dtls.test.example").is_some()
    };
    assert!(session_stored, "client should have cached the session");

    // 2nd connection: abbreviated handshake (session resumption)
    let cc2 = make_client_config(client_cache.clone());
    let sc2 = make_server_config(server_cache.clone());
    let (client2, server2) = dtls12_handshake_in_memory(cc2, sc2, false).unwrap();
    assert_eq!(client2.version(), Some(TlsVersion::Dtls12));
    assert_eq!(server2.version(), Some(TlsVersion::Dtls12));
}

/// DTLS 1.2 abbreviated: Data exchange works correctly after session resumption.
#[test]
fn test_dtls12_integration_abbreviated_data_exchange() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::session::InMemorySessionCache;
    use hitls_tls::CipherSuite;
    use std::sync::{Arc, Mutex};

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));
    let server_cache = Arc::new(Mutex::new(InMemorySessionCache::new(100)));

    let make_client_config = |cache: Arc<Mutex<InMemorySessionCache>>| {
        TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .verify_peer(false)
            .server_name("dtls.test.example")
            .session_cache(cache)
            .build()
    };

    let make_server_config = |cache: Arc<Mutex<InMemorySessionCache>>| {
        TlsConfig::builder()
            .cipher_suites(&[suite])
            .supported_groups(&groups)
            .signature_algorithms(&sig_algs)
            .certificate_chain(cert_chain.clone())
            .private_key(server_key.clone())
            .verify_peer(false)
            .session_cache(cache)
            .build()
    };

    // First: full handshake
    let (_, _) = dtls12_handshake_in_memory(
        make_client_config(client_cache.clone()),
        make_server_config(server_cache.clone()),
        false,
    )
    .unwrap();

    // Second: abbreviated handshake
    let (mut client, mut server) = dtls12_handshake_in_memory(
        make_client_config(client_cache),
        make_server_config(server_cache),
        false,
    )
    .unwrap();

    // Verify application data works after abbreviated handshake
    let datagram = client.seal_app_data(b"after resumption").unwrap();
    let pt = server.open_app_data(&datagram).unwrap();
    assert_eq!(pt, b"after resumption");

    let reply = server.seal_app_data(b"resumed ok").unwrap();
    let pt = client.open_app_data(&reply).unwrap();
    assert_eq!(pt, b"resumed ok");
}

/// DTLS 1.2: GREASE enabled on client -- handshake succeeds.
#[test]
fn test_dtls12_grease_enabled_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsVersion};

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

    let client_config = TlsConfig::builder()
        .cipher_suites(&[suite])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .grease(true)
        .verify_peer(false)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[suite])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let (mut client, mut server) =
        dtls12_handshake_in_memory(client_config, server_config, false).unwrap();
    assert_eq!(client.version(), Some(TlsVersion::Dtls12));
    assert_eq!(server.version(), Some(TlsVersion::Dtls12));

    // App data exchange
    let ct = client.seal_app_data(b"grease-dtls").unwrap();
    let pt = server.open_app_data(&ct).unwrap();
    assert_eq!(pt, b"grease-dtls");
}

/// DTLS 1.2: flight_transmit_enable and empty_records_limit config.
#[test]
fn test_dtls12_config_enhancements() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsVersion};

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

    // Config with custom DTLS settings
    let client_config = TlsConfig::builder()
        .cipher_suites(&[suite])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .verify_peer(false)
        .flight_transmit_enable(true)
        .empty_records_limit(64)
        .build();

    let server_config = TlsConfig::builder()
        .cipher_suites(&[suite])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .flight_transmit_enable(false)
        .empty_records_limit(100)
        .build();

    // Verify config values
    assert!(client_config.flight_transmit_enable);
    assert_eq!(client_config.empty_records_limit, 64);
    assert!(!server_config.flight_transmit_enable);
    assert_eq!(server_config.empty_records_limit, 100);

    // DTLS handshake should succeed with these configs
    let (mut client, mut server) =
        dtls12_handshake_in_memory(client_config, server_config, false).unwrap();
    assert_eq!(client.version(), Some(TlsVersion::Dtls12));
    assert_eq!(server.version(), Some(TlsVersion::Dtls12));

    let ct = client.seal_app_data(b"dtls-config-test").unwrap();
    let pt = server.open_app_data(&ct).unwrap();
    assert_eq!(pt, b"dtls-config-test");
}
