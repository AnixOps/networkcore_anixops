//! Malformed-input robustness for the shared codec and request parsers.
//!
//! Every parser that sees bytes from the network (frame decoder, request,
//! reply and UDP parsers) is fed random input, truncated streams and
//! single-byte corruptions of valid streams. None may panic, and an
//! authenticated framing must never hand back data that differs from what
//! was sent. The random source is a fixed-seed xorshift so failures repeat.

use std::sync::Arc;

use outbound_snell::request::{
    parse_reply, parse_request, parse_udp_downstream, parse_udp_upstream,
};
use outbound_snell::{CipherKind, Decoder, Encoder, Frame, Framing, V6Mode};

const PSK: &[u8] = b"robustness test psk";

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// (sender framing, receiver framing, authenticated)
fn framings() -> Vec<(&'static str, Framing, Framing, bool)> {
    let v6 = |mode| Framing::for_version(6, mode, PSK).unwrap();
    vec![
        (
            "v1",
            Framing::Legacy(CipherKind::ChaCha20Poly1305),
            Framing::LegacyAuto,
            true,
        ),
        (
            "v3",
            Framing::Legacy(CipherKind::Aes128Gcm),
            Framing::LegacyAuto,
            true,
        ),
        ("v4", Framing::V4, Framing::V4, true),
        ("v6-default", v6(V6Mode::Default), v6(V6Mode::Default), true),
        (
            "v6-unshaped",
            v6(V6Mode::Unshaped),
            v6(V6Mode::Unshaped),
            true,
        ),
        (
            "v6-unsafe-raw",
            v6(V6Mode::UnsafeRaw),
            v6(V6Mode::UnsafeRaw),
            false,
        ),
    ]
}

/// Feeds `input` in random pieces and collects frames until the decoder
/// errors or runs out of input.
fn drain(framing: Framing, input: &[u8], rng: &mut Rng) -> (Vec<Frame>, bool) {
    let mut decoder = Decoder::new(framing, Arc::from(PSK));
    let mut frames = Vec::new();
    let mut pos = 0;
    loop {
        match decoder.next_frame() {
            Ok(Some(frame)) => {
                frames.push(frame);
                continue;
            }
            Ok(None) => {}
            Err(_) => return (frames, true),
        }
        if pos == input.len() {
            return (frames, false);
        }
        let take = 1 + rng.below((input.len() - pos).min(4096));
        decoder.feed(&input[pos..pos + take]);
        pos += take;
    }
}

/// A valid stream: three data frames of assorted sizes and a zero chunk.
fn valid_stream(framing: &Framing, rng: &mut Rng) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut encoder = Encoder::new(framing.clone(), PSK).unwrap();
    let mut out = Vec::new();
    let mut sent = Vec::new();
    for len in [1, 300, 2000] {
        let data = rng.bytes(len);
        encoder.encode_single(&mut out, &data).unwrap();
        sent.push(data);
    }
    encoder.encode_zero(&mut out).unwrap();
    (out, sent)
}

/// Data frames joined, so frames split differently still compare equal.
fn data_of(frames: &[Frame]) -> Vec<u8> {
    frames
        .iter()
        .filter_map(|frame| match frame {
            Frame::Data(data) => Some(data.as_slice()),
            Frame::Zero => None,
        })
        .flatten()
        .copied()
        .collect()
}

#[test]
fn decoder_survives_random_input() {
    let mut rng = Rng(0x5eed_0001);
    for (name, _, receiver, _) in framings() {
        for round in 0..200 {
            let len = rng.below(if round % 10 == 0 { 70_000 } else { 600 });
            let input = rng.bytes(len);
            let (frames, _) = drain(receiver.clone(), &input, &mut rng);
            for frame in frames {
                if let Frame::Data(data) = frame {
                    assert!(
                        data.len() <= receiver.max_payload(),
                        "{name}: frame larger than the framing allows"
                    );
                }
            }
        }
    }
}

#[test]
fn valid_streams_round_trip_in_any_split() {
    let mut rng = Rng(0x5eed_0002);
    for (name, sender, receiver, _) in framings() {
        for _ in 0..20 {
            let (stream, sent) = valid_stream(&sender, &mut rng);
            let (frames, failed) = drain(receiver.clone(), &stream, &mut rng);
            assert!(!failed, "{name}: valid stream rejected");
            assert_eq!(data_of(&frames), sent.concat(), "{name}: data changed");
            assert_eq!(frames.last(), Some(&Frame::Zero), "{name}: zero chunk lost");
        }
    }
}

#[test]
fn truncated_streams_never_yield_wrong_data() {
    let mut rng = Rng(0x5eed_0003);
    for (name, sender, receiver, _) in framings() {
        let (stream, sent) = valid_stream(&sender, &mut rng);
        let expected = sent.concat();
        for cut in (0..stream.len()).step_by(7) {
            let (frames, failed) = drain(receiver.clone(), &stream[..cut], &mut rng);
            assert!(
                !failed,
                "{name}: truncated stream at {cut} reported an error"
            );
            let got = data_of(&frames);
            assert!(
                expected.starts_with(&got),
                "{name}: truncated stream at {cut} produced different data"
            );
        }
    }
}

#[test]
fn corrupted_streams_never_yield_wrong_data() {
    let mut rng = Rng(0x5eed_0004);
    for (name, sender, receiver, authenticated) in framings() {
        let (stream, sent) = valid_stream(&sender, &mut rng);
        let expected = sent.concat();
        for _ in 0..300 {
            let mut corrupted = stream.clone();
            let at = rng.below(corrupted.len());
            corrupted[at] ^= 1 << rng.below(8);
            let (frames, _) = drain(receiver.clone(), &corrupted, &mut rng);
            if authenticated {
                // Padding and filler bytes are not authenticated, so a flip
                // there may decode fine, but never into different data.
                let got = data_of(&frames);
                assert!(
                    expected.starts_with(&got),
                    "{name}: flipped byte {at} changed the decoded data"
                );
            }
        }
    }
}

#[test]
fn request_and_datagram_parsers_survive_random_input() {
    let mut rng = Rng(0x5eed_0005);
    for round in 0..50_000 {
        let len = rng.below(if round % 100 == 0 { 2048 } else { 64 });
        let mut input = rng.bytes(len);
        // Steer half the inputs past the version and command checks.
        if round % 2 == 0 && input.len() >= 2 {
            input[0] = 0x01;
            input[1] = [0x00, 0x01, 0x05, 0x06][rng.below(4)];
        }
        if let Ok(Some((request, used))) = parse_request(&input) {
            assert!(used <= input.len());
            assert!(request.client_id.len() <= 255);
        }
        if let Ok((_, used)) = parse_reply(&input) {
            assert!(used <= input.len());
        }
        let _ = parse_udp_upstream(&input);
        let _ = parse_udp_downstream(&input);
    }
}

#[test]
fn request_host_length_boundaries() {
    // A host of 255 bytes is the most one length byte can name.
    let host = "a".repeat(255);
    let mut input = vec![0x01, 0x05, 0x00, 255];
    input.extend_from_slice(host.as_bytes());
    input.extend_from_slice(&443u16.to_be_bytes());
    let (request, used) = parse_request(&input).unwrap().unwrap();
    assert_eq!(used, input.len());
    assert!(request.target.is_some());

    // One byte short of the port: needs more input, not an error.
    assert!(parse_request(&input[..input.len() - 1]).unwrap().is_none());

    // An empty host is malformed.
    assert!(parse_request(&[0x01, 0x05, 0x00, 0x00, 0x01, 0xbb]).is_err());

    // IPv6 literals in compressed form parse as addresses.
    let host = b"2001:db8::1";
    let mut input = vec![0x01, 0x05, 0x00, host.len() as u8];
    input.extend_from_slice(host);
    input.extend_from_slice(&443u16.to_be_bytes());
    let (request, _) = parse_request(&input).unwrap().unwrap();
    assert!(matches!(
        request.target,
        Some(engine_outbound::TargetAddr::Ip(addr)) if addr.is_ipv6()
    ));
}
