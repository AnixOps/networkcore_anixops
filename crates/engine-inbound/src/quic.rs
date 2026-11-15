//! The SNI of QUIC Initial packets, shared with the clients' kernel: see
//! [`engine_outbound::quic_sniff`].

pub(crate) use engine_outbound::quic_sniff::{is_initial, QuicHello, Sniffed};

#[cfg(test)]
mod tests {
    use engine_outbound::quic_sniff::testing::{client_hello, crypto, initial};
    use engine_outbound::quic_sniff::V1;
    use engine_outbound::TargetAddr;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|b| b.is_ascii_hexdigit())
            .map(|b| (b as char).to_digit(16).unwrap() as u8)
            .collect();
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    #[test]
    fn udp_flows_count_by_target_and_quic_name() {
        use crate::destinations::UdpDestinations;
        use crate::{User, UserStore};
        use std::net::SocketAddr;

        let store = UserStore::default();
        store.add(User::with_password("7", "secret")).unwrap();
        let mut flows = UdpDestinations::new(store.get("7"));

        let dns = TargetAddr::Domain("Dns.Example".into(), 53);
        flows.up(&dns, &[0u8; 30]);
        flows.down("198.51.100.53:53".parse().unwrap(), 70);

        let server: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let quic_target = TargetAddr::Ip(server);
        let hello = client_hello("video.example.com");
        let dcid = hex("0011223344556677");
        let one = initial(V1, &dcid, &crypto(0, &hello[..900]));
        let two = initial(V1, &dcid, &crypto(900, &hello[900..]));
        flows.up(&quic_target, &one);
        // A reply before the name shows waits with the flow.
        flows.down(server, 1000);
        flows.up(&quic_target, &two);
        flows.down(server, 5);

        let game = TargetAddr::Ip("192.0.2.1:27015".parse().unwrap());
        flows.up(&game, b"ping");
        flows.down("192.0.2.1:27015".parse().unwrap(), 6);

        let got: Vec<_> = store
            .destinations(true)
            .into_iter()
            .map(|entry| {
                (
                    entry.host,
                    entry.protocol,
                    entry.up,
                    entry.down,
                    entry.connections,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("192.0.2.1".into(), "udp".into(), 4, 6, 1),
                ("dns.example".into(), "udp".into(), 30, 70, 1),
                (
                    "video.example.com".into(),
                    "quic".into(),
                    (one.len() + two.len()) as u64,
                    1005,
                    1
                ),
            ]
        );
    }
}
