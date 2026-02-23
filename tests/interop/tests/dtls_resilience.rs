//! DTLS 1.2 loss simulation and resilience tests.
//!
//! Tests adverse delivery patterns on established DTLS connections:
//! out-of-order, selective loss, stale records, corruption, truncation,
//! empty datagrams, wrong epoch, and interleaved bidirectional out-of-order.

use hitls_integration_tests::*;
use hitls_tls::connection_dtls12::dtls12_handshake_in_memory;

/// Helper: establish a connected DTLS 1.2 pair.
fn connected_pair() -> (
    hitls_tls::connection_dtls12::Dtls12ClientConnection,
    hitls_tls::connection_dtls12::Dtls12ServerConnection,
) {
    let (cc, sc) = make_dtls12_configs();
    dtls12_handshake_in_memory(cc, sc, false).unwrap()
}

/// Deliver 5 sealed datagrams in reverse order — all should succeed within the
/// anti-replay window (window size = 64).
#[test]
fn test_dtls12_out_of_order_delivery() {
    let (mut client, mut server) = connected_pair();

    // Seal 5 messages in order
    let mut datagrams = Vec::new();
    for i in 0..5u32 {
        let msg = format!("ooo-msg-{i}");
        datagrams.push((msg.clone(), client.seal_app_data(msg.as_bytes()).unwrap()));
    }

    // Deliver in reverse order (4, 3, 2, 1, 0)
    for (msg, dg) in datagrams.iter().rev() {
        let pt = server
            .open_app_data(dg)
            .expect("out-of-order delivery within window should succeed");
        assert_eq!(pt, msg.as_bytes());
    }
}

/// Seal 10 messages, deliver only even-numbered ones (0, 2, 4, 6, 8),
/// simulating 50% packet loss. All delivered ones should succeed.
#[test]
fn test_dtls12_selective_loss_within_window() {
    let (mut client, mut server) = connected_pair();

    let mut datagrams = Vec::new();
    for i in 0..10u32 {
        let msg = format!("loss-msg-{i}");
        datagrams.push((msg.clone(), client.seal_app_data(msg.as_bytes()).unwrap()));
    }

    // Deliver only even-numbered datagrams
    for (i, (msg, dg)) in datagrams.iter().enumerate() {
        if i % 2 == 0 {
            let pt = server
                .open_app_data(dg)
                .expect("selectively delivered datagram should succeed");
            assert_eq!(pt, msg.as_bytes());
        }
    }
}

/// Seal 100 messages, deliver #1–#99 in order, then try delivering #0.
/// Message #0 should be rejected because its sequence number is outside the
/// 64-entry anti-replay window (max_seq=99, window covers 36..99).
#[test]
fn test_dtls12_stale_beyond_anti_replay_window() {
    let (mut client, mut server) = connected_pair();

    // Seal 100 messages
    let mut datagrams = Vec::new();
    for i in 0..100u32 {
        let msg = format!("stale-{i}");
        datagrams.push(client.seal_app_data(msg.as_bytes()).unwrap());
    }

    // Deliver messages #1 through #99 (skip #0)
    for dg in &datagrams[1..] {
        server.open_app_data(dg).unwrap();
    }

    // Now try delivering #0 — should be rejected (too old, outside window)
    let result = server.open_app_data(&datagrams[0]);
    assert!(
        result.is_err(),
        "stale record beyond anti-replay window should be rejected"
    );
}

/// Seal a message and flip a bit in the ciphertext portion — AEAD decryption
/// should fail due to integrity check.
#[test]
fn test_dtls12_corrupted_ciphertext_rejected() {
    let (mut client, mut server) = connected_pair();

    let mut datagram = client.seal_app_data(b"corrupt me").unwrap();

    // The record layout: 13-byte DTLS header + 8-byte explicit nonce + ciphertext + 16-byte tag.
    // The decryptor uses epoch/seq from the header (not the explicit nonce in the fragment),
    // so we must flip a byte in the actual ciphertext+tag area (starting at offset 13+8=21).
    assert!(datagram.len() > 25, "datagram should be long enough");
    datagram[25] ^= 0xFF;

    let result = server.open_app_data(&datagram);
    assert!(
        result.is_err(),
        "corrupted ciphertext should cause AEAD decryption failure"
    );
}

/// Truncate a sealed datagram to 10 bytes (less than the 13-byte DTLS header) —
/// parsing should fail.
#[test]
fn test_dtls12_truncated_record_rejected() {
    let (mut client, mut server) = connected_pair();

    let datagram = client.seal_app_data(b"truncate me").unwrap();

    // Truncate to only 10 bytes (less than 13-byte DTLS record header)
    let truncated = &datagram[..10];
    let result = server.open_app_data(truncated);
    assert!(
        result.is_err(),
        "truncated record (< 13 bytes) should be rejected"
    );
}

/// Pass an empty byte slice to `open_app_data()` — should return an error.
#[test]
fn test_dtls12_empty_datagram_rejected() {
    let (_, mut server) = connected_pair();

    let result = server.open_app_data(&[]);
    assert!(result.is_err(), "empty datagram should be rejected");
}

/// Seal a message and modify the epoch field (bytes 3..5) from epoch 1 to epoch 0.
/// This should cause AEAD decryption failure since the nonce includes the epoch.
#[test]
fn test_dtls12_wrong_epoch_record() {
    let (mut client, mut server) = connected_pair();

    let mut datagram = client.seal_app_data(b"wrong epoch").unwrap();

    // The epoch is stored in bytes 3..5 of the DTLS record header.
    // After handshake, epoch should be 1. Change it to 0.
    let original_epoch = u16::from_be_bytes([datagram[3], datagram[4]]);
    assert_eq!(original_epoch, 1, "post-handshake epoch should be 1");

    // Set epoch to 0
    datagram[3] = 0;
    datagram[4] = 0;

    let result = server.open_app_data(&datagram);
    assert!(
        result.is_err(),
        "wrong-epoch record should be rejected (AEAD nonce mismatch)"
    );
}

/// Both sides seal 5 messages each, then deliver them interleaved and
/// out-of-order — all should succeed.
#[test]
fn test_dtls12_interleaved_bidirectional_out_of_order() {
    let (mut client, mut server) = connected_pair();

    // Client seals 5 messages
    let mut client_datagrams = Vec::new();
    for i in 0..5u32 {
        let msg = format!("c2s-{i}");
        client_datagrams.push((msg.clone(), client.seal_app_data(msg.as_bytes()).unwrap()));
    }

    // Server seals 5 messages
    let mut server_datagrams = Vec::new();
    for i in 0..5u32 {
        let msg = format!("s2c-{i}");
        server_datagrams.push((msg.clone(), server.seal_app_data(msg.as_bytes()).unwrap()));
    }

    // Deliver client→server datagrams in reverse order
    for (msg, dg) in client_datagrams.iter().rev() {
        let pt = server.open_app_data(dg).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    // Deliver server→client datagrams in scrambled order: 3, 0, 4, 1, 2
    let order = [3, 0, 4, 1, 2];
    for &idx in &order {
        let (ref msg, ref dg) = server_datagrams[idx];
        let pt = client.open_app_data(dg).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }
}
