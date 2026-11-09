use tls_mimic::cert::{parse_leaf, verify_signature, OID_ED25519};
use tls_mimic::crypto::RecordCipher;
use tls_mimic::fingerprint::{build_from_spec, is_grease};
use tls_mimic::{
    build_client_hello, CipherSuite, ClientHelloSpec, Fingerprint, HashAlg, SESSION_ID_OFFSET,
};

fn hex(input: &str) -> Vec<u8> {
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
        .collect()
}

// Self-signed Ed25519 certificate (CN=tls-mimic.test) and a signature made
// with its key over b"tls-mimic certificate verify".
const ED25519_CERT: &str = "308201463081f9a00302010202145226102400ddd14371f7626eaa9d8e2faa23ec9b300506032b657030193117301506035504030c0e746c732d6d696d69632e74657374301e170d3236313032323135313631375a170d3336313031393135313631375a30193117301506035504030c0e746c732d6d696d69632e74657374302a300506032b65700321004c93aade0c99a63f456abfad2d4b10344a7e825441ede448e4fb6a32a3a8178fa3533051301d0603551d0e04160414c9cfe0e11f32dad1cd1b27be8860c92ae6249a6e301f0603551d23041830168014c9cfe0e11f32dad1cd1b27be8860c92ae6249a6e300f0603551d130101ff040530030101ff300506032b6570034100e69bfe5e70bca2b18cd89da619f7b016eb5582660e2ed511c759c8963f94977037d8aa9d118ba3676815507d0cf61b0227ba053c1e03c0a6914c2d80dbb23e0d";
const ED25519_PUBLIC: &str = "4c93aade0c99a63f456abfad2d4b10344a7e825441ede448e4fb6a32a3a8178f";
const ED25519_CERT_SIGNATURE: &str = "e69bfe5e70bca2b18cd89da619f7b016eb5582660e2ed511c759c8963f94977037d8aa9d118ba3676815507d0cf61b0227ba053c1e03c0a6914c2d80dbb23e0d";
const ED25519_MESSAGE_SIGNATURE: &str = "dd14b2cb7936bc9f28113c486b958d98e76333815c6b02e10d98d0096aea36be842836a78ebcdd8ed800abdec43d054afa6c4b498142f4678a94731bf2be290c";

#[test]
fn key_schedule_matches_rfc8448_early_secret() {
    let hash = HashAlg::Sha256;
    let zeros = [0u8; 32];
    let early = hash.hkdf_extract(&[], &zeros);
    assert_eq!(
        early,
        hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    );
    let derived = hash.derive_secret(&early, "derived", &hash.hash(&[]));
    assert_eq!(
        derived,
        hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
    );
}

#[test]
fn record_cipher_round_trips_and_rejects_tampering() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::Chacha20Poly1305Sha256,
    ] {
        let secret = vec![7u8; suite.hash().output_len()];
        let mut sealer = RecordCipher::new(suite, &secret).unwrap();
        let mut opener = RecordCipher::new(suite, &secret).unwrap();
        let mut wire = Vec::new();
        sealer.seal(23, b"first", &mut wire).unwrap();
        sealer.seal(22, b"second", &mut wire).unwrap();

        let first_len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        let (first, second) = wire.split_at(5 + first_len);
        let header: [u8; 5] = first[..5].try_into().unwrap();
        let mut payload = first[5..].to_vec();
        assert_eq!(opener.open(&header, &mut payload).unwrap(), 23);
        assert_eq!(payload, b"first");

        let header: [u8; 5] = second[..5].try_into().unwrap();
        let mut tampered = second[5..].to_vec();
        tampered[0] ^= 1;
        assert!(opener.open(&header, &mut tampered).is_err());
    }
}

#[test]
fn leaf_certificate_fields_and_ed25519_signature_verify() {
    let der = hex(ED25519_CERT);
    let leaf = parse_leaf(&der).expect("certificate parses");
    assert_eq!(leaf.public_key_algorithm, OID_ED25519);
    assert_eq!(leaf.public_key, hex(ED25519_PUBLIC).as_slice());
    assert_eq!(leaf.signature, hex(ED25519_CERT_SIGNATURE).as_slice());

    let signature = hex(ED25519_MESSAGE_SIGNATURE);
    verify_signature(0x0807, &leaf, b"tls-mimic certificate verify", &signature).unwrap();
    assert!(verify_signature(0x0807, &leaf, b"tampered message", &signature).is_err());
    assert!(verify_signature(0x0403, &leaf, b"tls-mimic certificate verify", &signature).is_err());
    assert!(parse_leaf(&der[..der.len() - 1]).is_none());
}

struct Hello {
    session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

fn parse_hello(message: &[u8]) -> Hello {
    assert_eq!(message[0], 1);
    let len = ((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize;
    assert_eq!(len + 4, message.len());
    let body = &message[4..];
    assert_eq!(&body[..2], &[3, 3]);
    assert_eq!(body[34], 32);
    let session_id = body[35..67].to_vec();
    let mut pos = 67;
    let suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let cipher_suites = body[pos..pos + suites_len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    pos += suites_len;
    assert_eq!(&body[pos..pos + 2], &[1, 0]);
    pos += 2;
    let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    assert_eq!(pos + ext_len, body.len());
    let mut extensions = Vec::new();
    while pos < body.len() {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        extensions.push((ext_type, body[pos + 4..pos + 4 + len].to_vec()));
        pos += 4 + len;
    }
    Hello {
        session_id,
        cipher_suites,
        extensions,
    }
}

fn extension(hello: &Hello, ext_type: u16) -> Option<&[u8]> {
    hello
        .extensions
        .iter()
        .find(|(t, _)| *t == ext_type)
        .map(|(_, data)| data.as_slice())
}

#[test]
fn chrome_client_hello_has_browser_shape() {
    let built = build_client_hello(Fingerprint::Chrome, "www.example.com", None).unwrap();
    let hello = parse_hello(&built.message);
    assert_eq!(
        &built.message[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32],
        hello.session_id.as_slice()
    );
    assert_eq!(&built.message[6..38], &built.random);

    assert!(is_grease(hello.cipher_suites[0]));
    assert_eq!(&hello.cipher_suites[1..4], &[0x1301, 0x1302, 0x1303]);
    assert_eq!(hello.cipher_suites.len(), 16);

    let first = hello.extensions.first().unwrap();
    let last = hello.extensions.last().unwrap();
    assert!(is_grease(first.0) && first.1.is_empty());
    assert!(is_grease(last.0) && last.1 == [0]);
    assert_ne!(first.0, last.0);
    assert_eq!(hello.extensions.len(), 18);

    let sni = extension(&hello, 0x0000).expect("SNI present");
    assert_eq!(&sni[5..], b"www.example.com");
    let alpn = extension(&hello, 0x0010).expect("ALPN present");
    assert_eq!(alpn, b"\x00\x0c\x02h2\x08http/1.1");
    let versions = extension(&hello, 0x002b).unwrap();
    assert_eq!(versions[0], 6);
    assert!(is_grease(u16::from_be_bytes([versions[1], versions[2]])));
    assert_eq!(&versions[3..], &[3, 4, 3, 3]);
    assert!(extension(&hello, 0xfe0d).is_some());
    assert!(extension(&hello, 0x44cd).is_some());

    // Chrome 157: GREASE signature scheme, then ML-DSA-44/65/87, then the classic list
    let sigalgs = extension(&hello, 0x000d).unwrap();
    let schemes: Vec<u16> = sigalgs[2..]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    assert!(is_grease(schemes[0]), "{schemes:04x?}");
    assert_eq!(
        &schemes[1..],
        &[0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
    );

    let shares = extension(&hello, 0x0033).unwrap();
    let mut pos = 2;
    let mut groups = Vec::new();
    while pos < shares.len() {
        let group = u16::from_be_bytes([shares[pos], shares[pos + 1]]);
        let len = u16::from_be_bytes([shares[pos + 2], shares[pos + 3]]) as usize;
        groups.push((group, shares[pos + 4..pos + 4 + len].to_vec()));
        pos += 4 + len;
    }
    assert_eq!(groups.len(), 3);
    assert!(is_grease(groups[0].0) && groups[0].1 == [0]);
    assert_eq!(groups[1].0, 0x11ec);
    assert_eq!(groups[1].1.len(), 1216);
    assert_eq!(groups[2].0, 0x001d);
    assert_eq!(groups[2].1.len(), 32);
    assert_eq!(&groups[1].1[1184..], groups[2].1.as_slice());

    let supported_groups = extension(&hello, 0x000a).unwrap();
    assert_eq!(
        u16::from_be_bytes([supported_groups[2], supported_groups[3]]),
        u16::from_be_bytes([shares[2], shares[3]]),
        "key share GREASE matches supported_groups GREASE"
    );
}

#[test]
fn chrome_permutes_extensions_and_omits_sni_for_ip_literals() {
    let orders: Vec<Vec<u16>> = (0..6)
        .map(|_| {
            let built = build_client_hello(Fingerprint::Chrome, "example.org", None).unwrap();
            parse_hello(&built.message)
                .extensions
                .iter()
                .map(|(t, _)| *t)
                .filter(|t| !is_grease(*t))
                .collect()
        })
        .collect();
    assert!(orders.iter().any(|order| order != &orders[0]));

    let built = build_client_hello(Fingerprint::ChromeNoPq, "192.0.2.1", None).unwrap();
    let hello = parse_hello(&built.message);
    assert!(extension(&hello, 0x0000).is_none());
    let shares = extension(&hello, 0x0033).unwrap();
    assert_eq!(shares.len(), 2 + 5 + 36);
}

#[test]
fn fingerprint_names_resolve() {
    assert_eq!(Fingerprint::from_name("chrome"), Some(Fingerprint::Chrome));
    assert_eq!(
        Fingerprint::from_name("Chrome-NoPQ"),
        Some(Fingerprint::ChromeNoPq)
    );
    assert_eq!(Fingerprint::from_name("firefox"), None);
    assert_eq!(Fingerprint::from_name("safari"), Some(Fingerprint::Safari));
    assert_eq!(Fingerprint::from_name("iOS"), Some(Fingerprint::Safari));
    assert_eq!(
        Fingerprint::from_name("auto"),
        Some(Fingerprint::platform_default())
    );
    let expected = if cfg!(target_vendor = "apple") {
        Fingerprint::Safari
    } else {
        Fingerprint::Chrome
    };
    assert_eq!(Fingerprint::platform_default(), expected);
    for fingerprint in Fingerprint::ALL {
        assert_eq!(
            Fingerprint::from_name(fingerprint.name()),
            Some(fingerprint)
        );
    }
}

/// Everything in a ClientHello that does not change from one connection to
/// the next: GREASE values become `G`, key shares keep group and length only.
fn shape(hello: &Hello) -> Vec<String> {
    let code = |value: u16| {
        if is_grease(value) {
            "G".to_owned()
        } else {
            format!("{value:04x}")
        }
    };
    let codes = |data: &[u8]| -> String {
        data.chunks(2)
            .map(|c| code(u16::from_be_bytes([c[0], c[1]])))
            .collect::<Vec<_>>()
            .join(",")
    };
    let plain = |data: &[u8]| data.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut out = vec![format!("suites {}", codes(&hello.cipher_suites_raw()))];
    for (ext_type, data) in &hello.extensions {
        let body = match *ext_type {
            0x000a => codes(&data[2..]),
            0x000d => codes(&data[2..]),
            0x002b => codes(&data[1..]),
            0x0033 => {
                let mut pos = 2;
                let mut shares = Vec::new();
                while pos < data.len() {
                    let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                    shares.push(format!("{}:{len}", code(group)));
                    pos += 4 + len;
                }
                shares.join(",")
            }
            _ => plain(data),
        };
        out.push(format!("{} {body}", code(*ext_type)));
    }
    out
}

impl Hello {
    fn cipher_suites_raw(&self) -> Vec<u8> {
        self.cipher_suites
            .iter()
            .flat_map(|suite| suite.to_be_bytes())
            .collect()
    }
}

/// The first packet Safari 26.6.2 sent on macOS 26.7.2 (one TLS record),
/// recorded by `anx-lab safari-fp` on 2026-11-09.
const SAFARI_CAPTURE: &str = include_str!("data/safari-26.6.2-macos-26.7.2.hex");

#[test]
fn safari_client_hello_matches_the_captured_one() {
    let record = hex(SAFARI_CAPTURE.trim());
    assert_eq!(&record[..3], &[0x16, 0x03, 0x01]);
    let captured = parse_hello(&record[5..]);

    for _ in 0..4 {
        let built = build_client_hello(Fingerprint::Safari, "localhost", None).unwrap();
        let ours = parse_hello(&built.message);
        assert_eq!(shape(&ours), shape(&captured));
        assert_eq!(built.message.len(), record.len() - 5);

        // The hybrid share ends with the same X25519 key as the standalone one.
        let shares = extension(&ours, 0x0033).unwrap();
        assert_eq!(&shares[shares.len() - 32..], &built.secrets.x25519_public());
        assert_eq!(
            &shares[11 + 1184..11 + 1216],
            &built.secrets.x25519_public()
        );
    }
}

#[test]
fn safari_keeps_its_extension_order_and_omits_sni_for_ip_literals() {
    let orders: Vec<Vec<u16>> = (0..4)
        .map(|_| {
            let built = build_client_hello(Fingerprint::Safari, "example.org", None).unwrap();
            parse_hello(&built.message)
                .extensions
                .iter()
                .map(|(t, _)| *t)
                .filter(|t| !is_grease(*t))
                .collect()
        })
        .collect();
    assert!(orders.iter().all(|order| order == &orders[0]));
    assert_eq!(
        orders[0],
        [
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d,
            0x002b, 0x001b
        ]
    );

    let built = build_client_hello(Fingerprint::Safari, "2001:db8::1", None).unwrap();
    let hello = parse_hello(&built.message);
    assert!(extension(&hello, 0x0000).is_none());
    // No ALPS, no ECH GREASE, no session ticket: those are Chrome's.
    for absent in [0x44cd, 0xfe0d, 0x0023, 0x0015] {
        assert!(extension(&hello, absent).is_none(), "{absent:04x}");
    }
}

#[test]
fn built_in_fingerprints_round_trip_through_json() {
    for fingerprint in Fingerprint::ALL {
        let spec = fingerprint.builtin_spec().unwrap();
        let again = ClientHelloSpec::from_json(&spec.to_json()).unwrap();
        assert_eq!(*spec, again, "{}", fingerprint.name());
    }
    assert!(
        Fingerprint::Chrome
            .builtin_spec()
            .unwrap()
            .permute_extensions
    );
    assert!(
        !Fingerprint::Safari
            .builtin_spec()
            .unwrap()
            .permute_extensions
    );
}

const SMALL_PROFILE: &str = r#"{
  "cipher_suites": ["grease", "0x1301", 4866],
  "extensions": [
    "grease",
    "server_name",
    { "type": "supported_groups", "groups": ["grease", "0x001d", "0x0017"] },
    { "type": "signature_algorithms", "schemes": ["0x0403", "0x0804"] },
    { "type": "key_share", "groups": ["grease", "0x001d"] },
    { "type": "supported_versions", "versions": ["grease", "0x0304"] },
    { "type": "raw", "id": "0x1234", "body": "00ff10" },
    "alpn",
    { "type": "grease", "body": "00" },
    "padding"
  ],
  "alpn": ["h2"]
}"#;

#[test]
fn profile_json_drives_the_client_hello() {
    let spec = ClientHelloSpec::from_json(SMALL_PROFILE).unwrap();
    assert!(!spec.permute_extensions);
    let built = build_from_spec(&spec, "example.com", None).unwrap();
    let hello = parse_hello(&built.message);
    assert_eq!(hello.cipher_suites.len(), 3);
    assert_eq!(&hello.cipher_suites[1..], &[0x1301, 0x1302]);
    assert_eq!(extension(&hello, 0x1234).unwrap(), [0x00, 0xff, 0x10]);
    assert_eq!(extension(&hello, 0x0010).unwrap(), b"\x00\x03\x02h2");
    let types: Vec<u16> = hello.extensions.iter().map(|(t, _)| *t).collect();
    assert!(is_grease(types[0]) && is_grease(types[8]));
    assert_eq!(
        &types[1..8],
        &[0x0000, 0x000a, 0x000d, 0x0033, 0x002b, 0x1234, 0x0010]
    );

    // BoringSSL padding: a ClientHello of 256 to 511 bytes is padded to 512,
    // with the padding extension where the profile lists it (here: last).
    assert!(built.message.len() < 256, "{}", built.message.len());
    assert!(extension(&hello, 0x0015).is_none());
    let long_name = format!("{}.example.com", "a".repeat(180));
    let built = build_from_spec(&spec, &long_name, None).unwrap();
    let hello = parse_hello(&built.message);
    assert_eq!(built.message.len(), 512);
    let (last_type, padding) = hello.extensions.last().unwrap();
    assert_eq!(*last_type, 0x0015);
    assert!(!padding.is_empty() && padding.iter().all(|byte| *byte == 0));
    let huge_name = format!("{}.{}.example.com", "a".repeat(200), "b".repeat(200));
    let built = build_from_spec(&spec, &huge_name, None).unwrap();
    assert!(built.message.len() > 512);
    assert!(extension(&parse_hello(&built.message), 0x0015).is_none());
}

#[test]
fn profile_json_is_strict() {
    let with = |from: &str, to: &str| {
        assert!(SMALL_PROFILE.contains(from), "{from}");
        ClientHelloSpec::from_json(&SMALL_PROFILE.replacen(from, to, 1))
    };
    // unknown key, unknown extension type, unknown parameter
    assert!(with("\"alpn\": [\"h2\"]", "\"alpn\": [\"h2\"], \"extra\": 1").is_err());
    assert!(with("\"server_name\"", "\"server_nam\"").is_err());
    assert!(with("\"body\": \"00ff10\"", "\"body\": \"00ff10\", \"x\": 1").is_err());
    // values that cannot be encoded
    assert!(with("4866", "70000").is_err());
    assert!(with("\"00ff10\"", "\"00ff1\"").is_err());
    assert!(with("\"0x1234\"", "\"0x12345\"").is_err());
    // a ClientHello this client cannot finish a handshake from
    assert!(with("\"0x1301\", 4866", "\"0xc02b\"").is_err());
    assert!(with("\"0x0304\"", "\"0x0303\"").is_err());
    assert!(with(
        "{ \"type\": \"key_share\", \"groups\": [\"grease\", \"0x001d\"] }",
        "{ \"type\": \"key_share\", \"groups\": [\"grease\", \"0x0017\"] }"
    )
    .is_err());
    assert!(with(
        "\"groups\": [\"grease\", \"0x001d\", \"0x0017\"]",
        "\"groups\": [\"0x001d\", \"0x0017\"]"
    )
    .is_err());
    // the same extension twice
    assert!(with("\"id\": \"0x1234\"", "\"id\": \"0x0010\"").is_err());
    assert!(ClientHelloSpec::from_json("[]").is_err());
    assert!(ClientHelloSpec::from_json(&" ".repeat(300 * 1024)).is_err());
}

#[test]
fn record_padding_changes_only_the_wire_length() {
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::Chacha20Poly1305Sha256,
    ] {
        let secret = vec![9u8; suite.hash().output_len()];
        let mut sealer = RecordCipher::new(suite, &secret).unwrap();
        let mut opener = RecordCipher::new(suite, &secret).unwrap();
        assert_eq!(sealer.overhead(), 17);
        for (content, padding) in [(&b"flight"[..], 0usize), (b"flight", 300), (b"", 64)] {
            let mut wire = Vec::new();
            sealer.seal_padded(22, content, padding, &mut wire).unwrap();
            let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
            assert_eq!(len, content.len() + padding + sealer.overhead());
            assert_eq!(wire.len(), 5 + len);
            let header: [u8; 5] = wire[..5].try_into().unwrap();
            let mut payload = wire[5..].to_vec();
            assert_eq!(opener.open(&header, &mut payload).unwrap(), 22);
            assert_eq!(payload, content);
        }
        // The whole inner plaintext (content + padding) is capped at 2^14.
        let mut wire = Vec::new();
        assert!(sealer
            .seal_padded(22, &[1u8; 16_000], 385, &mut wire)
            .is_err());
        assert!(sealer.seal_padded(0, b"x", 0, &mut wire).is_err());
        assert!(wire.is_empty());
        sealer
            .seal_padded(22, &[1u8; 16_000], 384, &mut wire)
            .unwrap();
        let header: [u8; 5] = wire[..5].try_into().unwrap();
        let mut payload = wire[5..].to_vec();
        assert_eq!(opener.open(&header, &mut payload).unwrap(), 22);
        assert_eq!(payload.len(), 16_000);
    }
}

/// A server sends NewSessionTicket-shaped handshake records right after the
/// handshake; the peer's stream skips them and delivers only application data.
#[tokio::test]
async fn post_handshake_records_are_sent_in_order_and_skipped_by_the_peer() {
    use tls_mimic::TlsStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let suite = CipherSuite::Aes128GcmSha256;
    let server_secret = vec![3u8; 32];
    let client_secret = vec![4u8; 32];
    let (server_io, mut wire) = tokio::io::duplex(64 * 1024);
    let mut server = TlsStream::from_secrets(
        server_io,
        suite,
        server_secret.clone(),
        client_secret.clone(),
        None,
    )
    .unwrap();

    // NewSessionTicket: type 4, 3-byte length, opaque body.
    let mut ticket = vec![4, 0, 0, 60];
    ticket.extend_from_slice(&[0xab; 60]);
    server.queue_handshake_record(&ticket, 0).unwrap();
    server.queue_handshake_record(&ticket, 100).unwrap();
    server.write_all(b"after tickets").await.unwrap();
    server.flush().await.unwrap();

    // On the wire: two handshake-sized records, then the application record.
    let mut bytes = vec![0u8; (5 + 64 + 17) + (5 + 164 + 17) + (5 + 13 + 17)];
    wire.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..5], &[0x17, 0x03, 0x03, 0x00, 81]);
    assert_eq!(&bytes[86..91], &[0x17, 0x03, 0x03, 0x00, 181]);
    assert_eq!(&bytes[272..277], &[0x17, 0x03, 0x03, 0x00, 30]);

    // The peer reads straight through the tickets.
    let (client_io, mut feed) = tokio::io::duplex(64 * 1024);
    feed.write_all(&bytes).await.unwrap();
    let mut client =
        TlsStream::from_secrets(client_io, suite, client_secret, server_secret, None).unwrap();
    let mut got = [0u8; 13];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"after tickets");
}
