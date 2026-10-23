use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use engine_outbound::TargetAddr;
use outbound_vless::protocol::encode_request_header;
use outbound_vless::reality::{derive_auth_key, seal_session_id, verify_temporary_certificate};
use outbound_vless::vision::{
    ReadStatus, TrafficState, VisionReader, VisionWriter, COMMAND_CONTINUE, MAX_FRAME_CONTENT,
};
use outbound_vless::{parse_public_key, parse_short_id, parse_uuid, Flow, RealityConfig};
use ring::{aead, hmac};
use tls_mimic::cert::parse_leaf;
use tls_mimic::{build_client_hello, Fingerprint, SESSION_ID_OFFSET};
use x25519_dalek::{PublicKey, StaticSecret};

const UUID: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
];

fn hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn parses_share_link_fields() {
    assert_eq!(
        parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap(),
        UUID
    );
    assert!(parse_uuid("b831381d-6324").is_err());
    assert_eq!(
        parse_short_id("0123abcd").unwrap(),
        [0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]
    );
    assert_eq!(parse_short_id("").unwrap(), [0u8; 8]);
    assert!(parse_short_id("012").is_err());
    assert!(parse_short_id("0123456789abcdef00").is_err());

    let key = [0xfbu8; 32];
    // base64url without padding, as printed by xray / sing-box.
    let encoded = "-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_v7-_s";
    assert_eq!(parse_public_key(encoded).unwrap(), key);
    assert_eq!(
        parse_public_key("+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/s=").unwrap(),
        key
    );
    assert!(parse_public_key("AAAA").is_err());
    assert_eq!(Flow::from_name("xtls-rprx-vision"), Some(Flow::Vision));
    assert_eq!(Flow::from_name(""), Some(Flow::None));
    assert_eq!(Flow::from_name("xtls-rprx-direct"), None);
}

#[test]
fn reality_config_debug_redacts_short_id() {
    let config = RealityConfig::new("www.example.com", [1u8; 32], [9u8; 8]);
    let debug = format!("{config:?}");
    assert!(debug.contains("www.example.com"));
    assert!(!debug.contains('9'));
}

#[test]
fn encodes_vless_request_headers() {
    let domain = TargetAddr::Domain("example.com".to_owned(), 443);
    let header = encode_request_header(&UUID, Flow::Vision, &domain).unwrap();
    let mut expected = vec![0u8];
    expected.extend_from_slice(&UUID);
    expected.push(18);
    expected.extend_from_slice(&[0x0a, 16]);
    expected.extend_from_slice(b"xtls-rprx-vision");
    expected.extend_from_slice(&[1, 0x01, 0xbb, 2, 11]);
    expected.extend_from_slice(b"example.com");
    assert_eq!(header, expected);

    let v4 = TargetAddr::from(SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 80)));
    let header = encode_request_header(&UUID, Flow::None, &v4).unwrap();
    assert_eq!(&header[17..], &[0, 1, 0, 80, 1, 10, 0, 0, 1]);

    let v6 = TargetAddr::from(SocketAddr::from((Ipv6Addr::LOCALHOST, 8080)));
    let header = encode_request_header(&UUID, Flow::None, &v6).unwrap();
    assert_eq!(&header[17..22], &[0, 1, 0x1f, 0x90, 3]);
    assert_eq!(header.len(), 22 + 16);

    let empty = TargetAddr::Domain(String::new(), 1);
    assert!(encode_request_header(&UUID, Flow::None, &empty).is_err());
}

#[test]
fn reality_session_id_decrypts_on_the_server_side() {
    let server_secret = StaticSecret::from([0x42u8; 32]);
    let server_public = PublicKey::from(&server_secret).to_bytes();
    let client_secret = StaticSecret::from([0x24u8; 32]);
    let client_public = PublicKey::from(&client_secret);

    let mut hello = build_client_hello(Fingerprint::Chrome, "www.example.com", None).unwrap();
    let random = hello.random;
    let client_shared = client_secret
        .diffie_hellman(&PublicKey::from(server_public))
        .to_bytes();
    let auth_key = derive_auth_key(&client_shared, &random);

    let mut plaintext = [0u8; 16];
    plaintext[..3].copy_from_slice(&[25, 10, 15]);
    plaintext[4..8].copy_from_slice(&1_790_000_000u32.to_be_bytes());
    plaintext[8..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    seal_session_id(&auth_key, &random, &plaintext, &mut hello.message).unwrap();

    // Server: same X25519 result, same HKDF, open with the zeroed hello as AAD.
    let server_shared = server_secret.diffie_hellman(&client_public).to_bytes();
    assert_eq!(server_shared, client_shared);
    let server_key = derive_auth_key(&server_shared, &random);
    let mut aad = hello.message.clone();
    let mut sealed = aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].to_vec();
    aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].fill(0);
    let key =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &server_key).unwrap());
    let nonce = aead::Nonce::try_assume_unique_for_key(&random[20..]).unwrap();
    let opened = key
        .open_in_place(nonce, aead::Aad::from(aad.as_slice()), &mut sealed)
        .unwrap();
    assert_eq!(&opened[..], &plaintext[..]);
}

// Ed25519 certificate from the tls-mimic contract tests; its signature field
// is replaced to emulate a REALITY temporary certificate.
const ED25519_CERT: &str = "308201463081f9a00302010202145226102400ddd14371f7626eaa9d8e2faa23ec9b300506032b657030193117301506035504030c0e746c732d6d696d69632e74657374301e170d3236313032323135313631375a170d3336313031393135313631375a30193117301506035504030c0e746c732d6d696d69632e74657374302a300506032b65700321004c93aade0c99a63f456abfad2d4b10344a7e825441ede448e4fb6a32a3a8178fa3533051301d0603551d0e04160414c9cfe0e11f32dad1cd1b27be8860c92ae6249a6e301f0603551d23041830168014c9cfe0e11f32dad1cd1b27be8860c92ae6249a6e300f0603551d130101ff040530030101ff300506032b6570034100e69bfe5e70bca2b18cd89da619f7b016eb5582660e2ed511c759c8963f94977037d8aa9d118ba3676815507d0cf61b0227ba053c1e03c0a6914c2d80dbb23e0d";

#[test]
fn reality_temporary_certificate_binding() {
    let auth_key = [0x5au8; 32];
    let mut der = hex(ED25519_CERT);
    assert!(!verify_temporary_certificate(&auth_key, &der));

    let public_key = parse_leaf(&der).unwrap().public_key.to_vec();
    let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, &auth_key), &public_key);
    let len = der.len();
    der[len - 64..].copy_from_slice(mac.as_ref());
    assert!(verify_temporary_certificate(&auth_key, &der));
    assert!(!verify_temporary_certificate(&[0x5bu8; 32], &der));
}

fn server_hello_packet(cipher: u16, tls13: bool) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x11; 32]);
    body.push(32);
    body.extend_from_slice(&[0x22; 32]);
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0);
    let extensions: &[u8] = if tls13 {
        &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
    } else {
        &[0xff, 0x01, 0x00, 0x01, 0x00, 0x00]
    };
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);
    let mut handshake = vec![2, 0, (body.len() >> 8) as u8, body.len() as u8];
    handshake.extend_from_slice(&body);
    let mut record = vec![
        0x16,
        3,
        3,
        (handshake.len() >> 8) as u8,
        handshake.len() as u8,
    ];
    record.extend_from_slice(&handshake);
    record
}

/// Feeds frames through a reader that plays the server, returning content.
fn unpad_all(frames: &[u8]) -> (Vec<u8>, ReadStatus, Vec<u8>) {
    let mut reader = VisionReader::new(UUID);
    let mut out = Vec::new();
    let mut status = ReadStatus::Padding;
    // Arbitrary split points must not matter.
    for piece in frames.chunks(7) {
        status = reader.feed(piece, &mut out);
    }
    (out, status, reader.take_pending())
}

#[test]
fn vision_frames_round_trip_and_switch_to_direct_on_tls13() {
    let mut traffic = TrafficState::default();
    let mut writer = VisionWriter::new(UUID);

    let mut frames = Vec::new();
    writer.pad(&[], COMMAND_CONTINUE, &mut frames).unwrap();
    assert_eq!(&frames[..16], &UUID);

    let mut client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x30, 0x01];
    client_hello.resize(0x35, 0xaa);
    assert!(!writer
        .encode(&mut traffic, &client_hello, &mut frames)
        .unwrap());
    assert!(traffic.is_tls);
    assert!(writer.is_padding());

    // The client's downlink sees a TLS 1.3 ServerHello with AES-128-GCM.
    traffic.filter(&server_hello_packet(0x1301, true));
    assert!(traffic.enable_xtls);
    assert_eq!(traffic.packets_to_filter, 0);

    let mut app_data = vec![0x17, 0x03, 0x03, 0x00, 0x20];
    app_data.resize(0x25, 0xbb);
    assert!(writer.encode(&mut traffic, &app_data, &mut frames).unwrap());
    assert!(!writer.is_padding());

    // After padding stops, writes pass through unchanged.
    let mut tail = Vec::new();
    assert!(!writer.encode(&mut traffic, b"raw", &mut tail).unwrap());
    assert_eq!(tail, b"raw");

    let (content, status, pending) = unpad_all(&frames);
    let mut expected = client_hello.clone();
    expected.extend_from_slice(&app_data);
    assert_eq!(content, expected);
    assert_eq!(status, ReadStatus::Direct);
    assert!(pending.is_empty());
}

#[test]
fn vision_ends_padding_for_tls12_and_non_tls_traffic() {
    let mut traffic = TrafficState::default();
    traffic.filter(&server_hello_packet(0xc02f, false));
    assert!(traffic.is_tls12_or_above && !traffic.enable_xtls);
    traffic.is_tls = true;
    let mut writer = VisionWriter::new(UUID);
    let mut frames = Vec::new();
    let mut app_data = vec![0x17, 0x03, 0x03, 0x00, 0x10];
    app_data.resize(0x15, 0xcc);
    assert!(!writer.encode(&mut traffic, &app_data, &mut frames).unwrap());
    let (content, status, _) = unpad_all(&frames);
    assert_eq!(content, app_data);
    assert_eq!(status, ReadStatus::End);

    // Plain HTTP: padding ends once the filter budget runs out.
    let mut traffic = TrafficState::default();
    let mut writer = VisionWriter::new(UUID);
    let mut frames = Vec::new();
    let mut sent = Vec::new();
    for i in 0..10u8 {
        let packet = vec![b'A' + i; 100];
        writer.encode(&mut traffic, &packet, &mut frames).unwrap();
        sent.extend_from_slice(&packet);
    }
    assert!(!writer.is_padding());
    let (content, status, _) = unpad_all(&frames);
    assert_eq!(status, ReadStatus::End);
    assert_eq!(content, sent);
}

#[test]
fn vision_splits_large_writes_and_passes_unpadded_downlink_through() {
    let mut traffic = TrafficState::default();
    let mut writer = VisionWriter::new(UUID);
    let mut frames = Vec::new();
    let large = vec![0x5a; MAX_FRAME_CONTENT * 2 + 10];
    writer.encode(&mut traffic, &large, &mut frames).unwrap();
    let mut reader = VisionReader::new(UUID);
    let mut content = Vec::new();
    assert_eq!(reader.feed(&frames, &mut content), ReadStatus::Padding);
    assert_eq!(content, large);

    let mut reader = VisionReader::new(UUID);
    let mut out = Vec::new();
    assert_eq!(reader.feed(b"short", &mut out), ReadStatus::Padding);
    assert!(out.is_empty());
    assert_eq!(reader.take_pending(), b"short");

    let mut reader = VisionReader::new(UUID);
    let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(reader.feed(plain, &mut out), ReadStatus::End);
    assert_eq!(out, plain);
}
