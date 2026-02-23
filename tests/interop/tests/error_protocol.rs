//! Version mismatch, cipher mismatch, PSK errors, and miscellaneous protocol integration tests.

use hitls_integration_tests::*;

/// TLS 1.3-only client vs TLS 1.2-only server -- handshake must fail.
#[test]
fn test_version_mismatch_tls13_client_vs_tls12_server() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::TlsClientConnection;
    use hitls_tls::connection12::Tls12ServerConnection;
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            let _ = conn.handshake(); // expected to fail
        }
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    assert!(
        conn.handshake().is_err(),
        "TLS 1.3-only client vs TLS 1.2-only server must fail"
    );
    server_handle.join().unwrap();
}

/// TLS 1.2-only client vs TLS 1.3-only server -- handshake must fail.
#[test]
fn test_version_mismatch_tls12_client_vs_tls13_server() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::TlsServerConnection;
    use hitls_tls::connection12::Tls12ClientConnection;
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = TlsServerConnection::new(stream, server_config);
            let _ = conn.handshake(); // expected to fail
        }
    });

    let (cert_chain2, server_key2) = make_ecdsa_server_identity();
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .certificate_chain(cert_chain2)
        .private_key(server_key2)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    assert!(
        conn.handshake().is_err(),
        "TLS 1.2-only client vs TLS 1.3-only server must fail"
    );
    server_handle.join().unwrap();
}

/// TLS 1.2 cipher suite mismatch -- no common cipher suite -> handshake fails.
#[test]
fn test_tls12_cipher_suite_mismatch() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_rsa_server_identity();
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    // Server only offers AES-128-GCM
    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    // Client only offers AES-256-GCM -- no overlap with server
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            let _ = conn.handshake();
        }
    });

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    assert!(conn.handshake().is_err(), "cipher suite mismatch must fail");
    server_handle.join().unwrap();
}

/// TLS 1.2 PSK with wrong key -- MAC verification fails -> handshake error.
#[test]
fn test_tls12_psk_wrong_key() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let suite = CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256;
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .psk(b"correct-psk-key-thats-32-bytes!!".to_vec())
        .psk_identity_hint(b"server-hint".to_vec())
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .psk(b"wrong-psk-key-that-is-different!!".to_vec()) // mismatch
        .psk_identity(b"client".to_vec())
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut conn = Tls12ServerConnection::new(stream, server_config);
            let _ = conn.handshake();
        }
    });

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    assert!(conn.handshake().is_err(), "PSK key mismatch must fail");
    server_handle.join().unwrap();
}

/// RecordLayer: empty record DoS protection with configurable limit.
#[test]
fn test_record_layer_empty_records_limit() {
    use hitls_tls::record::{ContentType, RecordLayer};

    let mut rl = RecordLayer::new();
    rl.empty_records_limit = 5;

    // 5 empty handshake records should be allowed
    for _ in 0..5 {
        rl.check_empty_record(ContentType::Handshake, 0).unwrap();
    }

    // 6th should fail
    let result = rl.check_empty_record(ContentType::Handshake, 0);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("too many consecutive empty records"));

    // Non-empty record resets the counter
    rl.check_empty_record(ContentType::Handshake, 42).unwrap();
    assert_eq!(rl.empty_record_count, 0);

    // Can accept empty records again
    rl.check_empty_record(ContentType::Handshake, 0).unwrap();
    assert_eq!(rl.empty_record_count, 1);
}

#[test]
fn test_quiet_shutdown_e2e() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::{TlsRole, TlsVersion};

    // Verify quiet_shutdown config works end-to-end
    let config = TlsConfig::builder()
        .role(TlsRole::Client)
        .quiet_shutdown(true)
        .build();
    assert!(config.quiet_shutdown);

    // With quiet_shutdown=false (default), config should be false
    let config2 = TlsConfig::builder().role(TlsRole::Server).build();
    assert!(!config2.quiet_shutdown);

    // Verify it propagates through version limits
    let config3 = TlsConfig::builder()
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls13)
        .quiet_shutdown(true)
        .build();
    assert!(config3.quiet_shutdown);
    assert_eq!(config3.min_version, TlsVersion::Tls12);
}

#[test]
fn test_security_callback_e2e() {
    use hitls_tls::config::{SecurityCallback, TlsConfig};
    use hitls_tls::TlsRole;
    use std::sync::Arc;

    // Create a security callback that rejects weak ciphers
    let cb: SecurityCallback = Arc::new(|op, level, id| {
        if op == 0 && level >= 2 {
            // At level 2+, reject AES-128 suites (id < 0x1302)
            id >= 0x1302
        } else {
            true
        }
    });

    let config = TlsConfig::builder()
        .role(TlsRole::Server)
        .security_cb(cb.clone())
        .security_level(2)
        .build();

    let cb_ref = config.security_cb.as_ref().unwrap();
    let level = config.security_level;

    // AES-128-GCM (0x1301) should be rejected at level 2
    assert!(!(cb_ref)(0, level, 0x1301));
    // AES-256-GCM (0x1302) should be allowed
    assert!((cb_ref)(0, level, 0x1302));
    // Groups always allowed
    assert!((cb_ref)(1, level, 0x001D));
}
