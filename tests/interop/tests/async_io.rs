//! Async tokio TLS 1.3/1.2 loopback integration tests.

use hitls_integration_tests::*;

#[tokio::test]
async fn test_async_tls13_loopback() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_async::{AsyncTlsClientConnection, AsyncTlsServerConnection};
    use hitls_tls::{AsyncTlsConnection, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    let (cert_chain, server_key) = make_ed25519_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = AsyncTlsServerConnection::new(stream, server_config);
        conn.handshake().await.unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"async hello from client!");

        conn.write(b"async hello from server!").await.unwrap();
        conn.shutdown().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut conn = AsyncTlsClientConnection::new(stream, client_config);
    conn.handshake().await.unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls13));

    conn.write(b"async hello from client!").await.unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"async hello from server!");

    conn.shutdown().await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_async_tls12_loopback() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection12_async::{AsyncTls12ClientConnection, AsyncTls12ServerConnection};
    use hitls_tls::crypt::{NamedGroup, SignatureScheme};
    use hitls_tls::{AsyncTlsConnection, CipherSuite, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    let (cert_chain, server_key) = make_ecdsa_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls12)
        .max_version(TlsVersion::Tls12)
        .supported_groups(&[NamedGroup::SECP256R1])
        .signature_algorithms(&[SignatureScheme::ECDSA_SECP256R1_SHA256])
        .cipher_suites(&[CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256])
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = AsyncTls12ServerConnection::new(stream, server_config);
        conn.handshake().await.unwrap();

        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"async TLS 1.2 hello!");

        conn.write(b"async TLS 1.2 reply!").await.unwrap();
        conn.shutdown().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut conn = AsyncTls12ClientConnection::new(stream, client_config);
    conn.handshake().await.unwrap();

    assert_eq!(conn.version(), Some(TlsVersion::Tls12));
    assert_eq!(
        conn.cipher_suite(),
        Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
    );

    conn.write(b"async TLS 1.2 hello!").await.unwrap();

    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"async TLS 1.2 reply!");

    conn.shutdown().await.unwrap();
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_async_tls13_large_payload() {
    use hitls_tls::config::TlsConfig;
    use hitls_tls::connection_async::{AsyncTlsClientConnection, AsyncTlsServerConnection};
    use hitls_tls::{AsyncTlsConnection, TlsRole, TlsVersion};
    use tokio::net::TcpListener;

    let (cert_chain, server_key) = make_ed25519_server_identity();

    let server_config = TlsConfig::builder()
        .role(TlsRole::Server)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .certificate_chain(cert_chain)
        .private_key(server_key)
        .verify_peer(false)
        .build();

    let client_config = TlsConfig::builder()
        .role(TlsRole::Client)
        .min_version(TlsVersion::Tls13)
        .max_version(TlsVersion::Tls13)
        .verify_peer(false)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // 64KB payload — must be chunked since TLS max fragment is 16384
    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let payload_clone = payload.clone();

    let server_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut conn = AsyncTlsServerConnection::new(stream, server_config);
        conn.handshake().await.unwrap();

        // Echo back everything
        let mut received = Vec::new();
        let mut buf = [0u8; 32768];
        while received.len() < payload_clone.len() {
            let n = conn.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload_clone);

        // Send it back in chunks
        let mut offset = 0;
        while offset < received.len() {
            let end = std::cmp::min(offset + 16000, received.len());
            conn.write(&received[offset..end]).await.unwrap();
            offset = end;
        }
        conn.shutdown().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut conn = AsyncTlsClientConnection::new(stream, client_config);
    conn.handshake().await.unwrap();

    // Send in chunks
    let mut offset = 0;
    while offset < payload.len() {
        let end = std::cmp::min(offset + 16000, payload.len());
        conn.write(&payload[offset..end]).await.unwrap();
        offset = end;
    }

    // Receive echo
    let mut received = Vec::new();
    let mut buf = [0u8; 32768];
    while received.len() < payload.len() {
        let n = conn.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    assert_eq!(received, payload);

    conn.shutdown().await.unwrap();
    server_handle.await.unwrap();
}
