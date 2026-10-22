use tls_mimic::cert::{parse_leaf, verify_signature, OID_ED25519};
use tls_mimic::crypto::RecordCipher;
use tls_mimic::fingerprint::is_grease;
use tls_mimic::{build_client_hello, CipherSuite, Fingerprint, HashAlg, SESSION_ID_OFFSET};

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
}
