//! TLS 1.2 handshake, features, and callback integration tests.

use hitls_integration_tests::*;

// -------------------------------------------------------
// 16. TCP loopback: TLS 1.2 ECDSA P-256
// -------------------------------------------------------
#[test]
fn test_tcp_tls12_loopback_ecdsa() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"TLS 1.2 works!");

        conn.write(b"TLS 1.2 confirmed!").unwrap();
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls12));

    conn.write(b"TLS 1.2 works!").unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"TLS 1.2 confirmed!");

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

// -------------------------------------------------------
// 18. TCP loopback: TLS 1.2 RSA
// -------------------------------------------------------
#[test]
#[ignore] // RSA 2048 key generation is slow
fn test_tcp_tls12_loopback_rsa() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_rsa_server_identity();

    let suites = [CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"RSA over TCP!");

        conn.write(b"RSA confirmed!").unwrap();
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    conn.write(b"RSA over TCP!").unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"RSA confirmed!");

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

// -------------------------------------------------------
// 20. TCP loopback: TLS 1.2 session ticket resumption
// -------------------------------------------------------
#[test]
fn test_tcp_tls12_session_ticket_loopback() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let ticket_key = vec![0xAB; 32];

    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    // --- First connection: full handshake, get ticket ---
    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain.clone())
        .private_key(server_key.clone())
        .verify_peer(false)
        .ticket_key(ticket_key.clone())
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .session_resumption(true)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"Full handshake!");
        conn.write(b"Got it!").unwrap();
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    assert_eq!(conn.version(), Some(TlsVersion::Tls12));

    conn.write(b"Full handshake!").unwrap();
    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"Got it!");

    // Get the session with ticket for resumption
    let session = conn.take_session().unwrap();
    assert!(session.ticket.is_some(), "should have received a ticket");

    conn.shutdown().unwrap();
    server_handle.join().unwrap();

    // --- Second connection: ticket-based resumption ---
    let server_config2 = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .ticket_key(ticket_key)
        .build();

    let client_config2 = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .session_resumption(true)
        .resumption_session(session)
        .build();

    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let server_handle2 = thread::spawn(move || {
        let (stream, _) = listener2.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config2);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"Resumed!");
        conn.write(b"Session ticket works!").unwrap();
        conn.shutdown().unwrap();
    });

    let stream2 = TcpStream::connect_timeout(&addr2, Duration::from_secs(5)).unwrap();
    stream2
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream2
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn2 = Tls12ClientConnection::new(stream2, client_config2);
    conn2.handshake().unwrap();
    assert_eq!(conn2.version(), Some(TlsVersion::Tls12));

    conn2.write(b"Resumed!").unwrap();
    let mut buf = [0u8; 256];
    let n = conn2.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"Session ticket works!");

    conn2.shutdown().unwrap();
    server_handle2.join().unwrap();
}

// -------------------------------------------------------
// 21. TCP loopback: TLS 1.2 EMS + ETM over CBC cipher suite
// -------------------------------------------------------
#[test]
fn test_tcp_tls12_ems_etm_loopback() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    // Use CBC suite so ETM applies
    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .enable_extended_master_secret(true)
        .enable_encrypt_then_mac(true)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .enable_extended_master_secret(true)
        .enable_encrypt_then_mac(true)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"EMS+ETM CBC works!");

        conn.write(b"EMS+ETM confirmed!").unwrap();
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls12));

    conn.write(b"EMS+ETM CBC works!").unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"EMS+ETM confirmed!");

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

// -------------------------------------------------------
// 22. TCP loopback: TLS 1.2 RSA static key exchange
// -------------------------------------------------------
#[test]
#[ignore] // RSA 2048 key generation is slow
fn test_tcp_tls12_loopback_rsa_static() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_rsa_server_identity();

    let suites = [CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256];
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"RSA static KX over TCP!");

        conn.write(b"RSA static confirmed!").unwrap();
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls12));
    assert_eq!(
        conn.cipher_suite(),
        Some(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256)
    );

    conn.write(b"RSA static KX over TCP!").unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"RSA static confirmed!");

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

// -------------------------------------------------------
// 23. TCP loopback: TLS 1.2 DHE_RSA key exchange
// -------------------------------------------------------
#[test]
#[ignore] // RSA 2048 key generation is slow
fn test_tcp_tls12_loopback_dhe_rsa() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_rsa_server_identity();

    let suites = [CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::FFDHE2048];
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"DHE over TCP!");

        conn.write(b"DHE confirmed!").unwrap();
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls12));
    assert_eq!(
        conn.cipher_suite(),
        Some(CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256)
    );

    conn.write(b"DHE over TCP!").unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"DHE confirmed!");

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

// -------------------------------------------------------
// mTLS integration tests
// -------------------------------------------------------

#[test]
fn test_tls12_mtls_loopback() {
    use hitls_tls::config::{ServerPrivateKey, TlsConfig};
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    // Also create a client ECDSA identity
    let client_kp =
        hitls_crypto::ecdsa::EcdsaKeyPair::generate(hitls_types::EccCurveId::NistP256).unwrap();
    let client_priv = client_kp.private_key_bytes();
    let client_sk = hitls_pki::x509::SigningKey::Ecdsa {
        curve_id: hitls_types::EccCurveId::NistP256,
        key_pair: client_kp,
    };
    let client_dn = hitls_pki::x509::DistinguishedName {
        entries: vec![("CN".into(), "client".into())],
    };
    let client_cert = hitls_pki::x509::CertificateBuilder::self_signed(
        client_dn,
        &client_sk,
        1_700_000_000,
        1_800_000_000,
    )
    .unwrap();

    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .verify_client_cert(true)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .client_certificate_chain(vec![client_cert.raw])
        .client_private_key(ServerPrivateKey::Ecdsa {
            curve_id: hitls_types::EccCurveId::NistP256,
            private_key: client_priv,
        })
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"mTLS client hello");
        conn.write(b"mTLS server reply").unwrap();
        conn.shutdown().unwrap();
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls12));
    conn.write(b"mTLS client hello").unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"mTLS server reply");

    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

#[test]
fn test_tls12_mtls_required_no_cert() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let suites = [CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .verify_client_cert(true)
        .require_client_cert(true)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&suites)
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        // No client cert provided
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        // Server should reject because client sends empty cert
        let result = conn.handshake();
        assert!(result.is_err(), "server should reject missing client cert");
    });

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    // Client handshake may also error out
    let _ = conn.handshake();

    server_handle.join().unwrap();
}

/// Five concurrent TLS 1.2 connections all succeed independently.
#[test]
fn test_concurrent_tls12_connections() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let sub_handles: Vec<_> = (0..5)
            .map(|_| {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let cc = cert_chain.clone();
                let pk = server_key.clone();
                thread::spawn(move || {
                    let cfg = TlsConfig::builder()
                        .role(TlsRole::Server)
                        .min_version(TlsVersion::Tls12)
                        .max_version(TlsVersion::Tls12)
                        .cipher_suites(&[suite])
                        .supported_groups(&groups)
                        .signature_algorithms(&sig_algs)
                        .certificate_chain(cc)
                        .private_key(pk)
                        .verify_peer(false)
                        .build();
                    let mut conn = Tls12ServerConnection::new(stream, cfg);
                    conn.handshake().unwrap();
                    let mut buf = [0u8; 64];
                    let n = conn.read(&mut buf).unwrap();
                    conn.write(&buf[..n]).unwrap();
                    let _ = conn.shutdown();
                })
            })
            .collect();
        for h in sub_handles {
            h.join().unwrap();
        }
    });

    let client_handles: Vec<_> = (0..5_usize)
        .map(|i| {
            thread::spawn(move || {
                let cfg = TlsConfig::builder()
                    .role(TlsRole::Client)
                    .min_version(TlsVersion::Tls12)
                    .max_version(TlsVersion::Tls12)
                    .cipher_suites(&[suite])
                    .supported_groups(&groups)
                    .signature_algorithms(&sig_algs)
                    .verify_peer(false)
                    .build();
                let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut conn = Tls12ClientConnection::new(stream, cfg);
                conn.handshake().unwrap();
                let msg = format!("tls12-client-{}", i);
                conn.write(msg.as_bytes()).unwrap();
                let mut buf = [0u8; 64];
                let n = conn.read(&mut buf).unwrap();
                assert_eq!(&buf[..n], msg.as_bytes());
                let _ = conn.shutdown();
            })
        })
        .collect();

    for h in client_handles {
        h.join().unwrap();
    }
    server_handle.join().unwrap();
}

/// TLS 1.2: 64 KB payload round-trip succeeds.
#[test]
fn test_tls12_large_64kb_payload() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_rsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let payload: Vec<u8> = (0u8..=255).cycle().take(65536).collect();
    let payload_for_server = payload.clone();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut received = Vec::new();
        while received.len() < 65536 {
            let mut buf = vec![0u8; 16384];
            let n = conn.read(&mut buf).unwrap();
            received.extend_from_slice(&buf[..n]);
        }
        tx.send(received).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(&payload).unwrap();
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let received = rx.recv().unwrap();
    assert_eq!(
        received, payload_for_server,
        "64KB TLS 1.2 payload must arrive intact"
    );
}

/// TLS 1.2 ConnectionInfo — cipher_suite, negotiated_group, session_resumed.
#[test]
fn test_tls12_connection_info_fields() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::connection_info::ConnectionInfo;
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];
    let (tx, rx) = mpsc::channel::<ConnectionInfo>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let info = conn.connection_info().unwrap();
        tx.send(info).unwrap();
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    let info = conn.connection_info().unwrap();
    assert_eq!(info.cipher_suite, suite);
    assert!(
        !info.session_resumed,
        "first TLS 1.2 connection is not resumed"
    );
    assert_eq!(
        info.negotiated_group,
        Some(NamedGroup::SECP256R1),
        "ECDHE must negotiate SECP256R1"
    );

    conn.write(b"info").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_info = rx.recv().unwrap();
    assert_eq!(server_info.cipher_suite, suite);
}

/// TLS 1.2: three sequential back-and-forth message exchanges on one connection.
#[test]
fn test_tls12_multi_message_exchange() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        for _ in 0..3 {
            let mut buf = [0u8; 64];
            let n = conn.read(&mut buf).unwrap();
            let mut reply = b"ack:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            conn.write(&reply).unwrap();
        }
        conn.shutdown().unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    for i in 0..3 {
        let msg = format!("msg{}", i);
        conn.write(msg.as_bytes()).unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).unwrap();
        let expected = format!("ack:{}", msg);
        assert_eq!(&buf[..n], expected.as_bytes(), "message {} roundtrip", i);
    }
    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

/// TLS 1.2: graceful shutdown sends close_notify on both sides without error.
#[test]
fn test_tls12_graceful_shutdown() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_rsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
    ];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 16];
        let _ = conn.read(&mut buf);
        conn.shutdown().unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"bye").unwrap();
    conn.shutdown().unwrap();
    server_handle.join().unwrap();
}

/// TLS 1.2: empty write returns without error.
#[test]
fn test_tls12_empty_write() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 16];
        let _ = conn.read(&mut buf);
        conn.write(b"ok").unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    // Empty write must succeed
    conn.write(b"").unwrap();
    // Follow with real data to unblock the server
    conn.write(b"data").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.2 export_keying_material: client and server derive the same material.
#[test]
fn test_tls12_export_keying_material_client_server_match() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let ekm = conn
            .export_keying_material(b"TESTING LABEL", Some(b"test context"), 32)
            .unwrap();
        tx.send(ekm).unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    let client_ekm = conn
        .export_keying_material(b"TESTING LABEL", Some(b"test context"), 32)
        .unwrap();
    assert_eq!(client_ekm.len(), 32);

    conn.write(b"done").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();

    server_handle.join().unwrap();
    let server_ekm = rx.recv().unwrap();
    assert_eq!(
        client_ekm, server_ekm,
        "TLS 1.2: client and server must derive identical keying material"
    );
}

/// TLS 1.2 session cache: InMemorySessionCache stores sessions; second connection
/// is resumed via session ticket (server with ticket_key + client with session_cache).
#[test]
fn test_tls12_session_cache_store_and_resume() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::session::InMemorySessionCache;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];
    // Server uses the same ticket_key for both connections so it can decrypt
    // tickets issued during the first handshake.
    let ticket_key = vec![0xAB; 32];

    // Shared client session cache
    let client_cache = Arc::new(Mutex::new(InMemorySessionCache::new(10)));

    // First connection: server issues a session ticket; client stores it in cache.
    let server_config1 = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain.clone())
        .private_key(server_key.clone())
        .ticket_key(ticket_key.clone())
        .verify_peer(false)
        .build();

    let listener1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr1 = listener1.local_addr().unwrap();

    let s1 = thread::spawn(move || {
        let (stream, _) = listener1.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config1);
        conn.handshake().unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        conn.write(b"ok").unwrap();
        let _ = conn.shutdown();
    });

    let client_cache_clone = client_cache.clone();
    let client_config1 = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .server_name("localhost")
        .session_cache(client_cache_clone)
        .session_resumption(true)
        .verify_peer(false)
        .build();

    let stream1 = std::net::TcpStream::connect_timeout(&addr1, Duration::from_secs(5)).unwrap();
    stream1
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream1
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn1 = Tls12ClientConnection::new(stream1, client_config1);
    conn1.handshake().unwrap();
    assert!(
        !conn1.is_session_resumed(),
        "first connection is never resumed"
    );
    conn1.write(b"hi").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn1.read(&mut buf);
    let _ = conn1.shutdown();
    s1.join().unwrap();

    // The client cache should now hold the ticket-based session for "localhost"
    assert!(
        !client_cache.lock().unwrap().is_empty(),
        "session with ticket should be stored in client cache after first connection"
    );

    // Second connection: server with the same ticket_key can decrypt the cached ticket.
    let server_config2 = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .ticket_key(ticket_key)
        .verify_peer(false)
        .build();

    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr2 = listener2.local_addr().unwrap();

    let s2 = thread::spawn(move || {
        let (stream, _) = listener2.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config2);
        conn.handshake().unwrap();
        assert!(
            conn.is_session_resumed(),
            "server: second connection should be resumed"
        );
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        conn.write(b"ok").unwrap();
        let _ = conn.shutdown();
    });

    let client_cache_clone2 = client_cache.clone();
    let client_config2 = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .server_name("localhost")
        .session_cache(client_cache_clone2)
        .session_resumption(true)
        .verify_peer(false)
        .build();

    let stream2 = std::net::TcpStream::connect_timeout(&addr2, Duration::from_secs(5)).unwrap();
    stream2
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream2
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn2 = Tls12ClientConnection::new(stream2, client_config2);
    conn2.handshake().unwrap();
    // Ticket in cache lets client offer it; server decrypts → abbreviated handshake
    assert!(
        conn2.is_session_resumed(),
        "second connection should be resumed from cached ticket"
    );
    conn2.write(b"hi").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn2.read(&mut buf);
    let _ = conn2.shutdown();
    s2.join().unwrap();
}

/// TLS 1.2: server-initiated renegotiation over TCP succeeds.
#[test]
fn test_tls12_renegotiation_server_initiated() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .allow_renegotiation(true)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();

        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"before renego");
        conn.write(b"ack1").unwrap();

        // Server initiates renegotiation (sends HelloRequest)
        conn.initiate_renegotiation().unwrap();

        // read() processes incoming ClientHello and completes re-handshake
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"after renego");
        conn.write(b"ack2").unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .allow_renegotiation(true)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();

    conn.write(b"before renego").unwrap();
    let mut buf = [0u8; 64];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ack1");

    // write() triggers HelloRequest processing → client re-handshakes
    conn.write(b"after renego").unwrap();
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ack2");
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.2: cert_verify_callback accepts despite no trusted certs.
#[test]
fn test_tls12_cert_verify_callback_accept() {
    use hitls_tls::config::{CertVerifyCallback, TlsConfig};
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        conn.write(b"ok").unwrap();
        let _ = conn.shutdown();
    });

    let cb: CertVerifyCallback = Arc::new(|_info| Ok(()));
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(true)
        .verify_hostname(false)
        .cert_verify_callback(cb)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"hi").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.2: key_log_callback logs CLIENT_RANDOM during handshake.
#[test]
fn test_tls12_key_log_callback_invoked() {
    use hitls_tls::config::{KeyLogCallback, TlsConfig};
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];
    let logged: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let ll = logged.clone();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        conn.write(b"ok").unwrap();
        let _ = conn.shutdown();
    });

    let cb: KeyLogCallback = Arc::new(move |line: &str| {
        ll.lock().unwrap().push(line.to_string());
    });
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .verify_peer(false)
        .key_log(cb)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"hi").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();
    server_handle.join().unwrap();

    let lines = logged.lock().unwrap();
    assert!(
        !lines.is_empty(),
        "key_log_callback must be invoked during TLS 1.2 handshake"
    );
    let has_client_random = lines.iter().any(|l| l.starts_with("CLIENT_RANDOM"));
    assert!(
        has_client_random,
        "TLS 1.2 key log must contain CLIENT_RANDOM, got: {lines:?}"
    );
}

/// TLS 1.2: SniCallback returns Accept — handshake succeeds.
#[test]
fn test_tls12_sni_callback_accept() {
    use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let cb: SniCallback = Arc::new(|_| SniAction::Accept);

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .sni_callback(cb)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .server_name("example.com")
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"tls12-sni").unwrap();
    let mut buf = [0u8; 16];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"tls12-sni");
    server_handle.join().unwrap();
}

/// TLS 1.2: SniCallback returns Reject — handshake fails.
#[test]
fn test_tls12_sni_callback_reject() {
    use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::SignatureScheme;
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    let groups = [hitls_tls::crypt::NamedGroup::SECP256R1];
    let sig_algs = [SignatureScheme::ECDSA_SECP256R1_SHA256];

    let cb: SniCallback = Arc::new(|_| SniAction::Reject);

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .sni_callback(cb)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        let _ = conn.handshake();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .supported_groups(&groups)
        .signature_algorithms(&sig_algs)
        .server_name("rejected.example.com")
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    let result = conn.handshake();
    assert!(
        result.is_err(),
        "handshake should fail when TLS 1.2 SniCallback rejects"
    );
    server_handle.join().unwrap();
}

// -------------------------------------------------------
// Testing-Phase 77 — G5: PskServerCallback integration tests
// -------------------------------------------------------

/// TLS 1.2 PSK: PskServerCallback returns key for known identity — handshake succeeds.
#[test]
fn test_tls12_psk_server_callback_known_identity() {
    use hitls_tls::config::{PskServerCallback, TlsConfig};
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let suite = CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256;
    let psk = b"test-psk-key-32-bytes-for-aes!!!".to_vec();
    let psk_clone = psk.clone();
    let identity = b"known-client".to_vec();

    // Server uses callback to look up PSK by identity
    let cb: PskServerCallback = Arc::new(move |id: &[u8]| {
        if id == b"known-client" {
            Some(psk_clone.clone())
        } else {
            None
        }
    });

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .verify_peer(false)
        .psk_server_callback(cb)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .verify_peer(false)
        .psk(psk)
        .psk_identity(identity)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"psk-callback").unwrap();
    let mut buf = [0u8; 16];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"psk-callback");
    server_handle.join().unwrap();
}

/// TLS 1.2 PSK: PskServerCallback returns None for unknown identity — handshake fails.
#[test]
fn test_tls12_psk_server_callback_unknown_identity() {
    use hitls_tls::config::{PskServerCallback, TlsConfig};
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let suite = CipherSuite::TLS_PSK_WITH_AES_128_GCM_SHA256;
    let psk = b"test-psk-key-32-bytes-for-aes!!!".to_vec();

    // Server callback never finds the identity → returns None
    let cb: PskServerCallback = Arc::new(|_id: &[u8]| None);

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .verify_peer(false)
        .psk_server_callback(cb)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        let _ = conn.handshake(); // Expected to fail
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[suite])
        .verify_peer(false)
        .psk(psk)
        .psk_identity(b"unknown-client".to_vec())
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    let result = conn.handshake();
    assert!(
        result.is_err(),
        "handshake should fail for unknown PSK identity"
    );
    server_handle.join().unwrap();
}

/// TLS 1.2: MsgCallback config accepted and handshake succeeds.
#[test]
fn test_tls12_msg_callback() {
    use hitls_tls::config::{MsgCallback, TlsConfig};
    use hitls_tls::connection12::{Tls12ClientConnection, Tls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ecdsa_server_identity();
    let messages: Arc<Mutex<Vec<(bool, u16, u8)>>> = Arc::new(Mutex::new(Vec::new()));
    let msgs = messages.clone();

    let cb: MsgCallback = Arc::new(move |outgoing, version, content_type, _data| {
        msgs.lock().unwrap().push((outgoing, version, content_type));
    });

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = Tls12ServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 32];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .verify_peer(false)
        .msg_callback(cb)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = Tls12ClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"hello12").unwrap();
    let _ = conn.shutdown();
    server_handle.join().unwrap();

    // msg_callback is configured but not yet wired into handshake call sites.
    // This test verifies the config is accepted and handshake succeeds.
    let _msgs = messages.lock().unwrap();
}
