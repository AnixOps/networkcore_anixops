//! The client session state machine (spec §5), without I/O.
//!
//! The driver owns the UDP socket and the server address. It calls
//! [`Client::start`] once, [`Client::tick`] about once a second,
//! [`Client::receive`] for every datagram from the server and
//! [`Client::encapsulate`] for every IP packet from the TUN side, and performs
//! the returned [`Output`]s in order. A connected UDP socket gives the
//! source address and port filter of spec §5.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::crypto::XorKey;
use crate::frag::Reassembler;
use crate::packet::{self, kind, EchoRequest, OpenRequest, Session};

/// OPEN is resent this often while authenticating.
pub const OPEN_INTERVAL: Duration = Duration::from_secs(2);
/// No session within this long after the last accepted packet resets.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(6);
/// ECHOREQ is sent this often once established.
pub const ECHO_INTERVAL: Duration = Duration::from_secs(2);
/// No accepted packet for this long resets an established session.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// Smallest server MTU that may lower the configured one.
pub const MIN_SERVER_MTU: u16 = 68;
pub const MIN_MTU: u16 = 46;
pub const MAX_MTU: u16 = 1600;
pub const DEFAULT_MTU: u16 = 1400;
const INITIAL_MIN_RTT_US: u32 = 5_000_000;

/// Validated client parameters. Holds the password, so it has no `Debug`.
#[derive(Clone)]
pub struct ClientConfig {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    /// 46..=1600.
    pub mtu: u16,
    pub encrypt: bool,
    /// 0..=32767.
    pub pipe_id: u16,
    /// 0 or 1.
    pub pipe_idx: u8,
    /// The server is a host name, resolved again after every reset.
    pub resolve: bool,
}

/// What the server handed out in OPENACK, for the platform's interface settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub address: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    /// Effective MTU: the configured one, lowered by the server's.
    pub mtu: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Waiting for the driver to resolve the server name.
    Resolving,
    Authenticating,
    Established,
    /// CLOSE or OPENREJ received; the next tick resets.
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Output {
    /// Resolve the server name (IPv4 only) and call [`Client::resolved`].
    Resolve,
    /// Close the UDP socket and open a new one (new source port). While
    /// resolving, the new socket waits for the resolved address.
    ResetSocket,
    /// Send this datagram to the server.
    Transmit(Vec<u8>),
    /// Write this IP packet to the TUN side.
    Deliver(Vec<u8>),
    /// A session is up with these settings.
    Established(Network),
    /// The server answered OPEN with OPENREJ (wrong user or password).
    Rejected,
    /// An established session ended; a new one is being set up.
    Disconnected,
    /// An ECHO round trip finished.
    Rtt { current_us: u32 },
}

/// ECHO latency in microseconds (spec §5 initial values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Latency {
    pub current_us: u32,
    pub min_us: u32,
    pub max_us: u32,
}

impl Default for Latency {
    fn default() -> Self {
        Self {
            current_us: 0,
            min_us: INITIAL_MIN_RTT_US,
            max_us: 0,
        }
    }
}

pub struct Client {
    config: ClientConfig,
    open: Vec<u8>,
    xor: XorKey,
    epoch: Instant,
    state: State,
    session: Session,
    encrypt: bool,
    network: Option<Network>,
    peer_dup: Option<u8>,
    last_open: Instant,
    last_echo: Instant,
    last_seen: Instant,
    latency: Latency,
    frags: Reassembler,
    dropped: u64,
}

impl Client {
    pub fn new(config: ClientConfig, now: Instant) -> Self {
        let open = packet::encode_open(&OpenRequest {
            username: &config.username,
            password: &config.password,
            mtu: config.mtu,
            encrypt: config.encrypt,
            pipe_id: config.pipe_id,
            pipe_idx: config.pipe_idx,
        });
        let xor = XorKey::new(&config.username, &config.password);
        let state = if config.resolve {
            State::Resolving
        } else {
            State::Authenticating
        };
        Self {
            config,
            open,
            xor,
            epoch: now,
            state,
            session: Session::default(),
            encrypt: false,
            network: None,
            peer_dup: None,
            last_open: now,
            last_echo: now,
            last_seen: now,
            latency: Latency::default(),
            frags: Reassembler::new(),
            dropped: 0,
        }
    }

    /// The first outputs: resolve the server, or send the first OPEN.
    pub fn start(&mut self, now: Instant, out: &mut Vec<Output>) {
        match self.state {
            State::Resolving => out.push(Output::Resolve),
            _ => self.enter_auth(now, out),
        }
    }

    /// The server name resolved; the driver has a socket connected to it.
    pub fn resolved(&mut self, now: Instant, out: &mut Vec<Output>) {
        if self.state == State::Resolving {
            self.enter_auth(now, out);
        }
    }

    pub fn tick(&mut self, now: Instant, out: &mut Vec<Output>) {
        self.frags.expire(now);
        let quiet = now.saturating_duration_since(self.last_seen);
        match self.state {
            State::Resolving => out.push(Output::Resolve),
            State::Authenticating => {
                if quiet > AUTH_TIMEOUT {
                    self.reset(now, out);
                } else if now.saturating_duration_since(self.last_open) >= OPEN_INTERVAL {
                    self.send_open(now, out);
                }
            }
            State::Established => {
                if quiet > IDLE_TIMEOUT {
                    self.reset(now, out);
                } else if now.saturating_duration_since(self.last_echo) >= ECHO_INTERVAL {
                    self.send_echo(now, out);
                }
            }
            State::Closed => self.reset(now, out),
        }
    }

    /// Handles one datagram from the server.
    pub fn receive(&mut self, now: Instant, datagram: &[u8], out: &mut Vec<Output>) {
        let Some(&kind) = datagram.first() else {
            return;
        };
        match kind {
            kind::OPENACK if self.state == State::Authenticating => {
                self.on_open_ack(now, datagram, out)
            }
            kind::OPENREJ if self.state == State::Authenticating => {
                // Not signature-checked and not counted as activity.
                if datagram.len() >= packet::HEADER_LEN {
                    self.state = State::Closed;
                    out.push(Output::Rejected);
                }
            }
            kind::DATA | kind::DATA_ENC if self.state == State::Established => {
                if let Some(packet) = self.open_data(datagram) {
                    self.last_seen = now;
                    out.push(Output::Deliver(packet));
                }
            }
            kind::ECHORESP if self.state == State::Established => {
                if let Some(sent_us) = packet::decode_echo_response(datagram) {
                    self.last_seen = now;
                    let rtt = self.micros(now).saturating_sub(sent_us);
                    let current_us = u32::try_from(rtt).unwrap_or(u32::MAX);
                    self.latency.current_us = current_us;
                    self.latency.min_us = self.latency.min_us.min(current_us);
                    self.latency.max_us = self.latency.max_us.max(current_us);
                    out.push(Output::Rtt { current_us });
                }
            }
            kind::CLOSE if self.state == State::Established => {
                if packet::verify_signed(datagram).is_some() {
                    self.last_seen = now;
                    self.state = State::Closed;
                }
            }
            kind::IPFRAG if self.state == State::Established => {
                let Some(fragment) = packet::decode_fragment(datagram) else {
                    return;
                };
                self.last_seen = now;
                if let Some(mut packet) = self.frags.push(now, fragment) {
                    // The session mode decides the mask here, not a type byte.
                    if self.encrypt {
                        self.xor.apply(&mut packet);
                    }
                    out.push(Output::Deliver(packet));
                }
            }
            kind::SEGRT if self.state == State::Established => {
                match packet::segrt_inner(datagram).and_then(|inner| self.open_data(inner)) {
                    Some(packet) => {
                        self.last_seen = now;
                        out.push(Output::Deliver(packet));
                    }
                    None => self.dropped += 1,
                }
            }
            _ => {}
        }
    }

    /// The datagram carrying one IP packet from the TUN side, or `None` when
    /// no session is up or the packet is empty.
    pub fn encapsulate(&self, ip: &[u8]) -> Option<Vec<u8>> {
        if self.state != State::Established || ip.is_empty() {
            return None;
        }
        let xor = self.encrypt.then_some(&self.xor);
        Some(packet::encode_data(self.session, xor, ip))
    }

    /// The CLOSE to send when the driver shuts down, if a session is up.
    pub fn close_datagram(&self) -> Option<Vec<u8>> {
        (self.state == State::Established).then(|| packet::encode_close(self.session))
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn network(&self) -> Option<&Network> {
        self.network.as_ref()
    }

    /// Whether the data plane is XOR-masked, as the server confirmed.
    pub fn encrypted(&self) -> bool {
        self.encrypt
    }

    /// The server's "peer dup pkt" flag, recorded only.
    pub fn peer_dup(&self) -> Option<u8> {
        self.peer_dup
    }

    pub fn latency(&self) -> Latency {
        self.latency
    }

    /// SEGRT datagrams the first version could not handle.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    fn on_open_ack(&mut self, now: Instant, datagram: &[u8], out: &mut Vec<Output>) {
        let Some(ack) = packet::decode_open_ack(datagram) else {
            return;
        };
        // Without a tunnel address the handshake failed: keep waiting.
        let Some(address) = ack.address.filter(|address| !address.is_unspecified()) else {
            return;
        };
        let mut mtu = self.config.mtu;
        if let Some(server_mtu) = ack.server_mtu {
            if server_mtu >= MIN_SERVER_MTU && server_mtu < mtu {
                mtu = server_mtu;
            }
        }
        let network = Network {
            address,
            dns: ack.dns,
            mtu,
        };
        self.session = ack.session;
        self.encrypt = ack.encrypt != 0;
        self.peer_dup = ack.peer_dup;
        self.network = Some(network.clone());
        self.state = State::Established;
        self.last_seen = now;
        // The first ECHO goes out one interval after the session is up.
        self.last_echo = now;
        out.push(Output::Established(network));
    }

    /// The IP packet of a DATA or DATA_ENC datagram; the type byte alone
    /// decides the mask, and the session fields are not checked.
    fn open_data(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        let kind = *datagram.first()?;
        let payload = datagram.get(packet::HEADER_LEN..)?;
        if payload.is_empty() {
            return None;
        }
        let mut packet = payload.to_vec();
        match kind {
            kind::DATA => {}
            kind::DATA_ENC => self.xor.apply(&mut packet),
            _ => return None,
        }
        Some(packet)
    }

    fn enter_auth(&mut self, now: Instant, out: &mut Vec<Output>) {
        self.state = State::Authenticating;
        self.last_seen = now;
        self.send_open(now, out);
    }

    fn send_open(&mut self, now: Instant, out: &mut Vec<Output>) {
        self.last_open = now;
        out.push(Output::Transmit(self.open.clone()));
    }

    fn send_echo(&mut self, now: Instant, out: &mut Vec<Output>) {
        self.last_echo = now;
        let echo = EchoRequest {
            sent_us: self.micros(now),
            current_us: self.latency.current_us,
            min_us: self.latency.min_us,
            max_us: self.latency.max_us,
            route_magic: 0,
        };
        out.push(Output::Transmit(packet::encode_echo_request(
            self.session,
            &echo,
        )));
    }

    /// Spec §5 reset: CLOSE and notify if a session was up, new socket, clear
    /// the session, then resolve again or send OPEN.
    fn reset(&mut self, now: Instant, out: &mut Vec<Output>) {
        if self.network.is_some() {
            out.push(Output::Transmit(packet::encode_close(self.session)));
            out.push(Output::Disconnected);
        }
        out.push(Output::ResetSocket);
        self.session = Session::default();
        self.encrypt = false;
        self.network = None;
        self.peer_dup = None;
        self.latency = Latency::default();
        self.frags.clear();
        if self.config.resolve {
            self.state = State::Resolving;
            self.last_seen = now;
            out.push(Output::Resolve);
        } else {
            self.enter_auth(now, out);
        }
    }

    fn micros(&self, now: Instant) -> u64 {
        u64::try_from(now.saturating_duration_since(self.epoch).as_micros()).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{encode_open_ack, tlv, Header};

    const SESSION: Session = Session {
        token: [0x12, 0x34],
        id: [9, 8, 7, 6],
    };

    fn config(resolve: bool, encrypt: bool) -> ClientConfig {
        ClientConfig {
            username: b"alice".to_vec(),
            password: b"secret".to_vec(),
            mtu: 1400,
            encrypt,
            pipe_id: 0,
            pipe_idx: 0,
            resolve,
        }
    }

    fn ack(encrypt: u8, mtu: u16) -> Vec<u8> {
        encode_open_ack(
            SESSION,
            encrypt,
            &[
                (tlv::MTU, &mtu.to_be_bytes()),
                (tlv::ADDRESS, &[10, 20, 30, 10]),
                (tlv::DNS0, &[1, 1, 1, 1]),
                (tlv::ENCRYPT, &[encrypt]),
            ],
        )
    }

    fn transmits(out: &[Output]) -> Vec<&[u8]> {
        out.iter()
            .filter_map(|output| match output {
                Output::Transmit(datagram) => Some(datagram.as_slice()),
                _ => None,
            })
            .collect()
    }

    fn established(encrypt: bool) -> (Client, Instant) {
        let now = Instant::now();
        let mut client = Client::new(config(false, encrypt), now);
        let mut out = Vec::new();
        client.start(now, &mut out);
        client.receive(now, &ack(u8::from(encrypt), 1400), &mut out);
        assert_eq!(client.state(), State::Established);
        (client, now)
    }

    #[test]
    fn handshake_sends_open_and_applies_ack() {
        let now = Instant::now();
        let mut client = Client::new(config(false, false), now);
        let mut out = Vec::new();
        client.start(now, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(transmits(&out)[0][0], kind::OPEN);
        out.clear();
        client.receive(now, &ack(0, 1380), &mut out);
        assert_eq!(
            out,
            vec![Output::Established(Network {
                address: Ipv4Addr::new(10, 20, 30, 10),
                dns: vec![Ipv4Addr::new(1, 1, 1, 1)],
                mtu: 1380,
            })]
        );
        assert!(!client.encrypted());
    }

    #[test]
    fn small_server_mtu_is_ignored() {
        let now = Instant::now();
        let mut client = Client::new(config(false, false), now);
        let mut out = Vec::new();
        client.start(now, &mut out);
        client.receive(now, &ack(0, 60), &mut out);
        assert_eq!(client.network().unwrap().mtu, 1400);
    }

    #[test]
    fn ack_without_address_keeps_waiting() {
        let now = Instant::now();
        let mut client = Client::new(config(false, false), now);
        let mut out = Vec::new();
        client.start(now, &mut out);
        let empty = encode_open_ack(SESSION, 0, &[(tlv::ADDRESS, &[0, 0, 0, 0])]);
        client.receive(now, &empty, &mut out);
        assert_eq!(client.state(), State::Authenticating);
    }

    #[test]
    fn open_is_resent_then_times_out() {
        let start = Instant::now();
        let mut client = Client::new(config(false, false), start);
        let mut out = Vec::new();
        client.start(start, &mut out);
        out.clear();
        client.tick(start + Duration::from_secs(1), &mut out);
        assert!(out.is_empty());
        client.tick(start + Duration::from_secs(2), &mut out);
        assert_eq!(transmits(&out).len(), 1);
        out.clear();
        client.tick(start + Duration::from_secs(7), &mut out);
        // Never established: no CLOSE, a new socket and a new OPEN.
        assert_eq!(out[0], Output::ResetSocket);
        assert_eq!(transmits(&out)[0][0], kind::OPEN);
    }

    #[test]
    fn rejection_closes_then_resets() {
        let now = Instant::now();
        let mut client = Client::new(config(false, false), now);
        let mut out = Vec::new();
        client.start(now, &mut out);
        out.clear();
        client.receive(now, &packet::encode_open_rej(), &mut out);
        assert_eq!(out, vec![Output::Rejected]);
        assert_eq!(client.state(), State::Closed);
        out.clear();
        client.tick(now + Duration::from_secs(1), &mut out);
        assert_eq!(out[0], Output::ResetSocket);
        assert_eq!(client.state(), State::Authenticating);
    }

    #[test]
    fn data_round_trip_plain_and_masked() {
        let (client, now) = established(false);
        let datagram = client.encapsulate(&[0x45, 1, 2]).unwrap();
        assert_eq!(datagram[0], kind::DATA);
        assert_eq!(&datagram[2..8], &[0x12, 0x34, 9, 8, 7, 6]);
        let mut client = client;
        let mut out = Vec::new();
        client.receive(now, &datagram, &mut out);
        assert_eq!(out, vec![Output::Deliver(vec![0x45, 1, 2])]);

        let (mut client, now) = established(true);
        assert!(client.encrypted());
        let datagram = client.encapsulate(&[0x45, 1, 2]).unwrap();
        assert_eq!(datagram[..2], [kind::DATA_ENC, 1]);
        assert_ne!(&datagram[8..], &[0x45, 1, 2]);
        let mut out = Vec::new();
        client.receive(now, &datagram, &mut out);
        // An empty DATA is dropped.
        client.receive(now, &datagram[..8], &mut out);
        assert_eq!(out, vec![Output::Deliver(vec![0x45, 1, 2])]);
    }

    #[test]
    fn nothing_is_sent_before_the_session() {
        let now = Instant::now();
        let mut client = Client::new(config(false, false), now);
        assert!(client.encapsulate(&[0x45]).is_none());
        let mut out = Vec::new();
        client.start(now, &mut out);
        out.clear();
        client.receive(now, &packet::encode_data(SESSION, None, &[1]), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn echo_measures_round_trip() {
        let (mut client, start) = established(false);
        let mut out = Vec::new();
        client.tick(start + Duration::from_secs(2), &mut out);
        let request = transmits(&out)[0].to_vec();
        assert_eq!(request[0], kind::ECHOREQ);
        assert_eq!(request.len(), 60);
        let mut response = request.clone();
        let header = Header::new(kind::ECHORESP, 0, SESSION).encode();
        response[..8].copy_from_slice(&header);
        response[8..24].copy_from_slice(&packet::signature(&header));
        out.clear();
        client.receive(
            start + Duration::from_secs(2) + Duration::from_millis(30),
            &response,
            &mut out,
        );
        assert_eq!(out, vec![Output::Rtt { current_us: 30_000 }]);
        assert_eq!(
            client.latency(),
            Latency {
                current_us: 30_000,
                min_us: 30_000,
                max_us: 30_000
            }
        );
    }

    #[test]
    fn idle_session_resets_with_close() {
        let (mut client, start) = established(false);
        let mut out = Vec::new();
        client.tick(start + Duration::from_secs(16), &mut out);
        assert_eq!(transmits(&out)[0], packet::encode_close(SESSION).as_slice());
        assert_eq!(out[1], Output::Disconnected);
        assert_eq!(out[2], Output::ResetSocket);
        assert_eq!(transmits(&out)[1][0], kind::OPEN);
        assert!(client.network().is_none());
    }

    #[test]
    fn server_close_ends_the_session() {
        let (mut client, now) = established(false);
        let mut out = Vec::new();
        let mut forged = packet::encode_close(SESSION);
        forged[20] ^= 1;
        client.receive(now, &forged, &mut out);
        assert_eq!(client.state(), State::Established);
        client.receive(now, &packet::encode_close(SESSION), &mut out);
        assert_eq!(client.state(), State::Closed);
        client.tick(now + Duration::from_secs(1), &mut out);
        assert!(out.contains(&Output::Disconnected));
    }

    #[test]
    fn host_names_are_resolved_again_after_reset() {
        let now = Instant::now();
        let mut client = Client::new(config(true, false), now);
        let mut out = Vec::new();
        client.start(now, &mut out);
        assert_eq!(out, vec![Output::Resolve]);
        out.clear();
        client.tick(now + Duration::from_secs(1), &mut out);
        assert_eq!(out, vec![Output::Resolve]);
        out.clear();
        client.resolved(now + Duration::from_secs(1), &mut out);
        assert_eq!(transmits(&out)[0][0], kind::OPEN);
        client.receive(now, &ack(0, 1400), &mut out);
        out.clear();
        client.tick(now + Duration::from_secs(20), &mut out);
        assert_eq!(out.last(), Some(&Output::Resolve));
        assert_eq!(client.state(), State::Resolving);
    }

    #[test]
    fn fragments_are_reassembled_and_unmasked() {
        let (mut client, now) = established(true);
        let key = XorKey::new(b"alice", b"secret");
        let mut whole = vec![0x45, 0, 0, 5, 9];
        key.apply(&mut whole);
        let mut out = Vec::new();
        for (offset, last, data) in [(3, true, &whole[3..]), (0, false, &whole[..3])] {
            let mut datagram = Header::new(kind::IPFRAG, 0, SESSION).encode().to_vec();
            datagram.extend_from_slice(&[0; 8]);
            datagram.extend_from_slice(&[1, 2, 3, 4]);
            datagram
                .extend_from_slice(&packet::fragment_bits(offset, data.len(), last).to_le_bytes());
            datagram.extend_from_slice(data);
            client.receive(now, &datagram, &mut out);
        }
        assert_eq!(out, vec![Output::Deliver(vec![0x45, 0, 0, 5, 9])]);
    }

    #[test]
    fn unsupported_segrt_is_counted() {
        let (mut client, now) = established(false);
        let mut datagram = Header::new(kind::SEGRT, 0, SESSION).encode().to_vec();
        datagram.extend_from_slice(&[0, 0, 3, 0]);
        datagram.extend_from_slice(&packet::encode_data(SESSION, None, &[1]));
        let mut out = Vec::new();
        client.receive(now, &datagram, &mut out);
        assert!(out.is_empty());
        assert_eq!(client.dropped(), 1);
        datagram[packet::HEADER_LEN + 2] = 0;
        client.receive(now, &datagram, &mut out);
        assert_eq!(out, vec![Output::Deliver(vec![1])]);
    }
}
