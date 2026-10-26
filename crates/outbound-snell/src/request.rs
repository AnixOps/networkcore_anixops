//! Plaintext requests, replies and UDP datagram headers (spec §3, §4.1).
//! Shared by clients and servers.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use engine_outbound::TargetAddr;

use crate::crypto::{invalid_data, invalid_input};

pub const REQUEST_VERSION: u8 = 0x01;

pub const REPLY_TUNNEL: u8 = 0x00;
pub const REPLY_PONG: u8 = 0x01;
pub const REPLY_ERROR: u8 = 0x02;

/// A reusable request's target closed before sending anything.
pub const ERROR_REMOTE_EOF: u8 = 0x65;
/// v4/v5 one-shot CONNECT: the target closed before sending anything.
pub const ERROR_ONE_SHOT_EOF: u8 = 0xFF;

const UDP_FAMILY_V4: u8 = 0x04;
const UDP_FAMILY_V6: u8 = 0x06;
const UDP_UPSTREAM: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Ping,
    /// One-shot CONNECT (v1, and v2/v3 without reuse).
    Connect,
    /// Reusable CONNECT (v4+, and v2/v3 with reuse).
    ConnectV2,
    Udp,
}

impl Command {
    pub fn code(self) -> u8 {
        match self {
            Command::Ping => 0x00,
            Command::Connect => 0x01,
            Command::ConnectV2 => 0x05,
            Command::Udp => 0x06,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Command::Ping),
            0x01 => Some(Command::Connect),
            0x05 => Some(Command::ConnectV2),
            0x06 => Some(Command::Udp),
            _ => None,
        }
    }
}

/// A parsed request. `client_id` is the multi-user server's user key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub command: Command,
    pub client_id: Vec<u8>,
    pub target: Option<TargetAddr>,
}

/// Appends a request. `target` is required for the CONNECT commands.
pub fn encode_request(
    out: &mut Vec<u8>,
    command: Command,
    client_id: &[u8],
    target: Option<&TargetAddr>,
) -> io::Result<()> {
    if client_id.len() > 255 {
        return Err(invalid_input("snell user key is longer than 255 bytes"));
    }
    out.push(REQUEST_VERSION);
    out.push(command.code());
    if command == Command::Ping {
        return Ok(());
    }
    out.push(client_id.len() as u8);
    out.extend_from_slice(client_id);
    if matches!(command, Command::Connect | Command::ConnectV2) {
        let target = target.ok_or_else(|| invalid_input("snell connect request needs a target"))?;
        let host = target.host();
        if host.is_empty() || host.len() > 255 {
            return Err(invalid_input("target host length is out of range"));
        }
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
        out.extend_from_slice(&target.port().to_be_bytes());
    }
    Ok(())
}

/// Parses a request at the start of `buf`. Returns the request and its
/// length, or `None` when `buf` is too short.
pub fn parse_request(buf: &[u8]) -> io::Result<Option<(Request, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    if buf[0] != REQUEST_VERSION {
        return Err(invalid_data("snell request version is invalid"));
    }
    let command = Command::from_code(buf[1])
        .ok_or_else(|| invalid_data("snell request command is unknown"))?;
    if command == Command::Ping {
        let request = Request {
            command,
            client_id: Vec::new(),
            target: None,
        };
        return Ok(Some((request, 2)));
    }
    let Some(&id_len) = buf.get(2) else {
        return Ok(None);
    };
    let mut pos = 3 + usize::from(id_len);
    let Some(client_id) = buf.get(3..pos) else {
        return Ok(None);
    };
    let client_id = client_id.to_vec();
    let target = if command == Command::Udp {
        None
    } else {
        let Some(&host_len) = buf.get(pos) else {
            return Ok(None);
        };
        let host_start = pos + 1;
        let host_end = host_start + usize::from(host_len);
        let Some(port) = buf.get(host_end..host_end + 2) else {
            return Ok(None);
        };
        let port = u16::from_be_bytes([port[0], port[1]]);
        let host = std::str::from_utf8(&buf[host_start..host_end])
            .map_err(|_| invalid_data("snell request host is not text"))?;
        if host.is_empty() {
            return Err(invalid_data("snell request host is empty"));
        }
        pos = host_end + 2;
        Some(target_from_host(host, port))
    };
    Ok(Some((
        Request {
            command,
            client_id,
            target,
        },
        pos,
    )))
}

fn target_from_host(host: &str, port: u16) -> TargetAddr {
    match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
        Err(_) => TargetAddr::Domain(host.to_owned(), port),
    }
}

/// The first plaintext of a server's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// TUNNEL / READY; for TCP the target's first bytes follow.
    Tunnel,
    Pong,
    Error {
        code: u8,
        message: Vec<u8>,
    },
}

/// Appends an ERROR reply. Messages are cut at 250 bytes.
pub fn encode_error(out: &mut Vec<u8>, code: u8, message: &[u8]) {
    let message = &message[..message.len().min(250)];
    out.push(REPLY_ERROR);
    out.push(code);
    out.push(message.len() as u8);
    out.extend_from_slice(message);
}

/// Parses the reply at the start of the first frame. Returns the reply and
/// the offset of the data after it. An ERROR frame must hold nothing else.
pub fn parse_reply(frame: &[u8]) -> io::Result<(Reply, usize)> {
    match frame.first() {
        Some(&REPLY_TUNNEL) => Ok((Reply::Tunnel, 1)),
        Some(&REPLY_PONG) => Ok((Reply::Pong, 1)),
        Some(&REPLY_ERROR) => {
            if frame.len() < 3 || frame.len() != 3 + usize::from(frame[2]) {
                return Err(invalid_data("snell error reply is malformed"));
            }
            Ok((
                Reply::Error {
                    code: frame[1],
                    message: frame[3..].to_vec(),
                },
                frame.len(),
            ))
        }
        _ => Err(invalid_data("snell reply is invalid")),
    }
}

/// Appends an upstream UDP datagram: `0x01`, address, port, payload.
pub fn encode_udp_upstream(
    out: &mut Vec<u8>,
    target: &TargetAddr,
    payload: &[u8],
) -> io::Result<()> {
    out.push(UDP_UPSTREAM);
    match target {
        TargetAddr::Domain(domain, _) => {
            if domain.is_empty() || domain.len() > 255 {
                return Err(invalid_input("target domain length is out of range"));
            }
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
        TargetAddr::Ip(addr) => {
            out.push(0x00);
            push_ip(out, addr.ip());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Parses an upstream UDP datagram into its target and payload.
pub fn parse_udp_upstream(frame: &[u8]) -> io::Result<(TargetAddr, &[u8])> {
    let malformed = || invalid_data("snell udp datagram is malformed");
    if frame.first() != Some(&UDP_UPSTREAM) {
        return Err(malformed());
    }
    let kind = *frame.get(1).ok_or_else(malformed)?;
    let (host, rest) = if kind == 0x00 {
        let (ip, rest) = read_ip(&frame[2..]).ok_or_else(malformed)?;
        (Err(ip), rest)
    } else {
        let end = 2 + usize::from(kind);
        let domain = frame.get(2..end).ok_or_else(malformed)?;
        let domain = std::str::from_utf8(domain).map_err(|_| malformed())?;
        (Ok(domain.to_owned()), &frame[end..])
    };
    let port = rest.get(..2).ok_or_else(malformed)?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    let target = match host {
        Ok(domain) => target_from_host(&domain, port),
        Err(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
    };
    Ok((target, &rest[2..]))
}

/// Appends a downstream UDP datagram: family, IP, port, payload.
pub fn encode_udp_downstream(out: &mut Vec<u8>, source: SocketAddr, payload: &[u8]) {
    push_ip(out, source.ip());
    out.extend_from_slice(&source.port().to_be_bytes());
    out.extend_from_slice(payload);
}

/// Parses a downstream UDP datagram. `None` for an unknown address family,
/// which the client drops.
pub fn parse_udp_downstream(frame: &[u8]) -> io::Result<Option<(SocketAddr, &[u8])>> {
    if !matches!(frame.first(), Some(&UDP_FAMILY_V4) | Some(&UDP_FAMILY_V6)) {
        return Ok(None);
    }
    let malformed = || invalid_data("snell udp datagram is malformed");
    let (ip, rest) = read_ip(frame).ok_or_else(malformed)?;
    let port = rest.get(..2).ok_or_else(malformed)?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    Ok(Some((SocketAddr::new(ip, port), &rest[2..])))
}

fn push_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => {
            out.push(UDP_FAMILY_V4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(UDP_FAMILY_V6);
            out.extend_from_slice(&ip.octets());
        }
    }
}

/// Reads family byte and IP; returns the rest.
fn read_ip(buf: &[u8]) -> Option<(IpAddr, &[u8])> {
    match *buf.first()? {
        UDP_FAMILY_V4 => {
            let raw: [u8; 4] = buf.get(1..5)?.try_into().ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(raw)), &buf[5..]))
        }
        UDP_FAMILY_V6 => {
            let raw: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(raw)), &buf[17..]))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let targets = [
            TargetAddr::Domain("example.com".into(), 443),
            TargetAddr::Ip("1.2.3.4:80".parse().unwrap()),
            TargetAddr::Ip("[2001:db8::1]:53".parse().unwrap()),
        ];
        for target in &targets {
            for command in [Command::Connect, Command::ConnectV2] {
                let mut buf = Vec::new();
                encode_request(&mut buf, command, b"user", Some(target)).unwrap();
                buf.extend_from_slice(b"payload");
                let (request, len) = parse_request(&buf).unwrap().unwrap();
                assert_eq!(request.command, command);
                assert_eq!(request.client_id, b"user");
                assert_eq!(request.target.as_ref(), Some(target));
                assert_eq!(&buf[len..], b"payload");
                for short in 0..len {
                    assert!(parse_request(&buf[..short]).unwrap().is_none());
                }
            }
        }
        let mut buf = Vec::new();
        encode_request(&mut buf, Command::ConnectV2, b"", Some(&targets[2])).unwrap();
        // IPv6 literals are written without brackets.
        assert_eq!(&buf[3..5], &[11, b'2']);
        assert_eq!(&buf[4..15], b"2001:db8::1");

        let mut ping = Vec::new();
        encode_request(&mut ping, Command::Ping, b"ignored", None).unwrap();
        assert_eq!(ping, [1, 0]);
        let mut udp = Vec::new();
        encode_request(&mut udp, Command::Udp, b"", None).unwrap();
        assert_eq!(udp, [1, 6, 0]);
        assert_eq!(parse_request(&udp).unwrap().unwrap().1, 3);
        assert!(parse_request(&[2, 1]).is_err());
        assert!(parse_request(&[1, 9]).is_err());
    }

    #[test]
    fn replies_parse_strictly() {
        assert_eq!(parse_reply(&[0, 9, 9]).unwrap(), (Reply::Tunnel, 1));
        let mut error = Vec::new();
        encode_error(&mut error, ERROR_REMOTE_EOF, b"Remote EOF");
        let (reply, len) = parse_reply(&error).unwrap();
        assert_eq!(
            reply,
            Reply::Error {
                code: ERROR_REMOTE_EOF,
                message: b"Remote EOF".to_vec()
            }
        );
        assert_eq!(len, error.len());
        error.push(0);
        assert!(parse_reply(&error).is_err());
        assert!(parse_reply(&[7]).is_err());
    }

    #[test]
    fn udp_datagrams_round_trip() {
        for target in [
            TargetAddr::Domain("dns.example".into(), 53),
            TargetAddr::Ip("8.8.8.8:53".parse().unwrap()),
            TargetAddr::Ip("[::1]:5353".parse().unwrap()),
        ] {
            let mut frame = Vec::new();
            encode_udp_upstream(&mut frame, &target, b"query").unwrap();
            let (parsed, payload) = parse_udp_upstream(&frame).unwrap();
            assert_eq!(parsed, target);
            assert_eq!(payload, b"query");
        }
        for source in ["9.9.9.9:53", "[2001:db8::2]:443"] {
            let source: SocketAddr = source.parse().unwrap();
            let mut frame = Vec::new();
            encode_udp_downstream(&mut frame, source, b"answer");
            let (parsed, payload) = parse_udp_downstream(&frame).unwrap().unwrap();
            assert_eq!((parsed, payload), (source, &b"answer"[..]));
        }
        assert!(parse_udp_downstream(&[0x05, 1, 2]).unwrap().is_none());
        assert!(parse_udp_downstream(&[0x04, 1, 2]).is_err());
    }
}
