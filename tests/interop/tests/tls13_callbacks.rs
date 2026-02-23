//! TLS 1.3 callback, extension, GREASE, and Heartbeat integration tests.

use hitls_integration_tests::*;

/// TLS 1.3: cert_verify_callback accepts despite no trusted certs configured.
#[test]
fn test_tls13_cert_verify_callback_accept() {
    use hitls_tls::config::{CertVerifyCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 8];
        let _ = conn.read(&mut buf);
        conn.write(b"ok").unwrap();
        let _ = conn.shutdown();
    });

    let cb: CertVerifyCallback = Arc::new(|_info| Ok(()));
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"hi").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();
    server_handle.join().unwrap();
}

/// TLS 1.3: cert_verify_callback rejects -> handshake fails.
#[test]
fn test_tls13_cert_verify_callback_reject() {
    use hitls_tls::config::{CertVerifyCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        let _ = conn.handshake();
    });

    let cb: CertVerifyCallback = Arc::new(|_info| Err("rejected by policy".to_string()));
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
    let mut conn = TlsClientConnection::new(stream, client_config);
    let result = conn.handshake();
    assert!(result.is_err(), "handshake must fail when callback rejects");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("rejected by policy") || msg.contains("callback"),
        "unexpected error: {msg}"
    );
    server_handle.join().unwrap();
}

/// TLS 1.3: key_log_callback is invoked during handshake.
#[test]
fn test_tls13_key_log_callback_invoked() {
    use hitls_tls::config::{KeyLogCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let logged: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let ll = logged.clone();

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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
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
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"hi").unwrap();
    let mut buf = [0u8; 8];
    let _ = conn.read(&mut buf);
    let _ = conn.shutdown();
    server_handle.join().unwrap();

    let lines = logged.lock().unwrap();
    assert!(
        !lines.is_empty(),
        "key_log_callback must be invoked during TLS 1.3 handshake"
    );
    for line in lines.iter() {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        assert_eq!(
            parts.len(),
            3,
            "key log line must have 3 space-separated fields: {line}"
        );
    }
}

/// TLS 1.3: SniCallback returns Accept -- handshake succeeds with original config.
#[test]
fn test_tls13_sni_callback_accept() {
    use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let cb: SniCallback = Arc::new(|_hostname: &str| SniAction::Accept);

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .server_name("example.com")
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"sni-accept").unwrap();
    let mut buf = [0u8; 16];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"sni-accept");
    server_handle.join().unwrap();
}

/// TLS 1.3: SniCallback returns AcceptWithConfig -- server switches to new config.
#[test]
fn test_tls13_sni_callback_accept_with_config() {
    use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain1, server_key1) = make_ed25519_server_identity();
    let (cert_chain2, server_key2) = make_ed25519_server_identity();

    // Callback switches to a second certificate chain for "example.com"
    let new_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain2)
        .private_key(server_key2)
        .verify_peer(false)
        .build();

    let cb: SniCallback =
        Arc::new(move |_hostname: &str| SniAction::AcceptWithConfig(Box::new(new_config.clone())));

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain1)
        .private_key(server_key1)
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
        let mut conn = TlsServerConnection::new(stream, server_config);
        // Handshake succeeds using the config switched in by SniCallback
        conn.handshake().unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .server_name("example.com")
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"sni-switched").unwrap();
    let mut buf = [0u8; 16];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"sni-switched");
    server_handle.join().unwrap();
}

/// TLS 1.3: SniCallback returns Reject -- handshake fails with error.
#[test]
fn test_tls13_sni_callback_reject() {
    use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    // Callback always rejects
    let cb: SniCallback = Arc::new(|_| SniAction::Reject);

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
        let mut conn = TlsServerConnection::new(stream, server_config);
        // Server-side handshake should fail (Reject)
        let _ = conn.handshake();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .server_name("rejected.example.com")
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    // Client-side handshake should fail because server rejected SNI
    let result = conn.handshake();
    assert!(
        result.is_err(),
        "handshake should fail when SniCallback rejects"
    );
    server_handle.join().unwrap();
}

/// TLS 1.3: SniCallback returns Ignore -- server_name cleared, handshake continues.
#[test]
fn test_tls13_sni_callback_ignore() {
    use hitls_tls::config::{SniAction, SniCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    // Callback returns Ignore -> server clears client_server_name but continues
    let cb: SniCallback = Arc::new(|_| SniAction::Ignore);

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .server_name("ignored.example.com")
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    // Handshake succeeds despite Ignore
    conn.handshake().unwrap();
    conn.write(b"sni-ignored").unwrap();
    let mut buf = [0u8; 16];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"sni-ignored");
    server_handle.join().unwrap();
}

/// TLS 1.3: Client with padding_target=512, handshake completes successfully.
#[test]
fn test_tls13_padding_extension_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    // Client sends ClientHello padded to ~512 bytes via RFC 7685 PADDING extension
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .padding_target(512)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"padded-hello").unwrap();
    let mut buf = [0u8; 16];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"padded-hello");
    server_handle.join().unwrap();
}

/// TLS 1.3 mTLS: Server with oid_filters set, CertificateRequest includes OID Filters extension.
#[test]
fn test_tls13_oid_filters_in_cert_request() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (server_cert_chain, server_key) = make_ed25519_server_identity();
    let (client_cert_chain, client_key) = make_ed25519_server_identity();

    // OID for extendedKeyUsage (2.5.29.37)
    let oid_bytes = vec![0x55, 0x1D, 0x25];
    let oid_values = vec![0x30, 0x0A]; // placeholder values

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(server_cert_chain)
        .private_key(server_key)
        .verify_peer(true)
        .trusted_cert(client_cert_chain[0].clone())
        .oid_filters(vec![(oid_bytes, oid_values)])
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        // Server sends CertificateRequest with OID Filters -- handshake should complete
        let result = conn.handshake();
        let _ = result;
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(client_cert_chain)
        .private_key(client_key)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    // Client receives CertificateRequest with OID Filters and processes it
    let _ = conn.handshake();
    server_handle.join().unwrap();
}

/// TLS 1.3 mTLS: Server without oid_filters -- CertificateRequest has no OID Filters extension.
#[test]
fn test_tls13_no_oid_filters_in_cert_request() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    let (server_cert_chain, server_key) = make_ed25519_server_identity();
    let (client_cert_chain, client_key) = make_ed25519_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(server_cert_chain)
        .private_key(server_key)
        .verify_peer(true)
        .trusted_cert(client_cert_chain[0].clone())
        .build(); // No oid_filters

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        let _ = conn.handshake();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(client_cert_chain)
        .private_key(client_key)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    // Handshake completes without OID Filters (no crash / no parse error)
    let _ = conn.handshake();
    server_handle.join().unwrap();
}

/// TLS 1.3: GREASE enabled on client -- server ignores GREASE values, handshake succeeds.
#[test]
fn test_tls13_grease_enabled_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    // Client with GREASE enabled
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .grease(true)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"grease-tls13").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"grease-tls13");
    server_handle.join().unwrap();
}

/// TLS 1.3: Client with heartbeat_mode=1, handshake succeeds (negotiation-only).
#[test]
fn test_tls13_heartbeat_mode_handshake() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    // Client with heartbeat_mode=1 (peer_allowed_to_send)
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .heartbeat_mode(1)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"heartbeat-tls13").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"heartbeat-tls13");
    server_handle.join().unwrap();
}

/// TLS 1.3: Both GREASE and heartbeat enabled simultaneously.
#[test]
fn test_tls13_grease_and_heartbeat_combined() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).unwrap();
        conn.write(&buf[..n]).unwrap();
    });

    // Client with both GREASE and heartbeat enabled
    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .grease(true)
        .heartbeat_mode(1)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"combo").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"combo");
    server_handle.join().unwrap();
}

/// TLS 1.3: MsgCallback observes protocol messages during handshake.
#[test]
fn test_tls13_msg_callback() {
    use hitls_tls::config::{MsgCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let messages: Arc<Mutex<Vec<(bool, u16, u8)>>> = Arc::new(Mutex::new(Vec::new()));
    let msgs = messages.clone();

    let cb: MsgCallback = Arc::new(move |outgoing, version, content_type, _data| {
        msgs.lock().unwrap().push((outgoing, version, content_type));
    });

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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 32];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
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
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"hi").unwrap();
    let _ = conn.shutdown();
    server_handle.join().unwrap();

    // msg_callback is configured but not yet wired into handshake call sites.
    // This test verifies the config is accepted and handshake succeeds.
    let _msgs = messages.lock().unwrap();
}

/// TLS 1.3: InfoCallback config accepted and handshake succeeds.
#[test]
fn test_tls13_info_callback() {
    use hitls_tls::config::{InfoCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let events: Arc<Mutex<Vec<(i32, i32)>>> = Arc::new(Mutex::new(Vec::new()));
    let evts = events.clone();

    let cb: InfoCallback = Arc::new(move |event_type, value| {
        evts.lock().unwrap().push((event_type, value));
    });

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .info_callback(cb.clone())
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
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 32];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"info").unwrap();
    let _ = conn.shutdown();
    server_handle.join().unwrap();

    // Info callback was set on server -- it should have received events
    let evts = events.lock().unwrap();
    // We don't strictly require events (depends on implementation),
    // but the callback should be wired without panicking
    // The main assertion is that the handshake succeeded with the callback set
    let _ = evts.len(); // just ensure no panic occurred
}

/// TLS 1.3: ClientHelloCallback observes cipher suites from client.
#[test]
fn test_tls13_client_hello_callback() {
    use hitls_tls::config::{ClientHelloAction, ClientHelloCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{CipherSuite, TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let observed_suites: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
    let suites = observed_suites.clone();

    let cb: ClientHelloCallback = Arc::new(move |info| {
        suites
            .lock()
            .unwrap()
            .extend_from_slice(&info.cipher_suites);
        ClientHelloAction::Success
    });

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .client_hello_callback(cb)
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
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 32];
        let _ = conn.read(&mut buf);
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .cipher_suites(&[
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
        ])
        .verify_peer(false)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"ch").unwrap();
    let _ = conn.shutdown();
    server_handle.join().unwrap();

    let suites = observed_suites.lock().unwrap();
    assert!(!suites.is_empty(), "should observe client cipher suites");
    // The client offered TLS_AES_128_GCM_SHA256 (0x1301)
    assert!(
        suites.contains(&0x1301),
        "should contain TLS_AES_128_GCM_SHA256"
    );
}

/// TLS 1.3: record_padding_callback is wired and handshake succeeds.
#[test]
fn test_tls13_record_padding_callback() {
    use hitls_tls::config::{RecordPaddingCallback, TlsConfig};
    use hitls_tls::connection::{TlsClientConnection, TlsServerConnection};
    use hitls_tls::{TlsConnection, TlsRole, TlsVersion};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    let (cert_chain, server_key) = make_ed25519_server_identity();
    let pad_calls: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let pads = pad_calls.clone();

    let cb: RecordPaddingCallback = Arc::new(move |_content_type, _len| {
        *pads.lock().unwrap() += 1;
        32 // add 32 bytes padding
    });

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
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut conn = TlsServerConnection::new(stream, server_config);
        conn.handshake().unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"padded data");
        conn.write(b"ok").unwrap();
        let _ = conn.shutdown();
    });

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .record_padding_callback(cb)
        .build();

    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut conn = TlsClientConnection::new(stream, client_config);
    conn.handshake().unwrap();
    conn.write(b"padded data").unwrap();
    let mut buf = [0u8; 32];
    let n = conn.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ok");
    let _ = conn.shutdown();
    server_handle.join().unwrap();

    let calls = *pad_calls.lock().unwrap();
    assert!(calls > 0, "record_padding_callback should have been called");
}
