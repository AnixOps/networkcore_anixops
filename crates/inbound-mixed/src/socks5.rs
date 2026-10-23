//! SOCKS5 (RFC 1928) `CONNECT` with optional username/password (RFC 1929).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use engine_outbound::TargetAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::{invalid, read_exact, Credentials, Reply, Request};

pub(crate) const VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const METHOD_NONE: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_UNACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
pub(crate) const REP_SUCCEEDED: u8 = 0x00;
pub(crate) const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

/// A reply with an all-zero IPv4 bound address; clients ignore it for CONNECT.
pub(crate) fn reply(code: u8) -> [u8; 10] {
    [VERSION, code, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

pub(crate) async fn read_request(
    client: &mut TcpStream,
    credentials: Option<&Credentials>,
) -> io::Result<Request> {
    let mut head = [0u8; 2];
    read_exact(client, &mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    read_exact(client, &mut methods).await?;

    let wanted = if credentials.is_some() {
        METHOD_PASSWORD
    } else {
        METHOD_NONE
    };
    if !methods.contains(&wanted) {
        client.write_all(&[VERSION, METHOD_UNACCEPTABLE]).await?;
        return Err(invalid("no acceptable socks5 method"));
    }
    client.write_all(&[VERSION, wanted]).await?;
    if let Some(expected) = credentials {
        authenticate(client, expected).await?;
    }

    let mut request = [0u8; 4];
    read_exact(client, &mut request).await?;
    if request[0] != VERSION {
        return Err(invalid("bad socks5 request version"));
    }
    if request[1] != CMD_CONNECT {
        client.write_all(&reply(REP_COMMAND_NOT_SUPPORTED)).await?;
        return Err(invalid("unsupported socks5 command"));
    }
    let target = match request[3] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            read_exact(client, &mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            TargetAddr::Ip(SocketAddr::from((ip, u16::from_be_bytes([buf[4], buf[5]]))))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            read_exact(client, &mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = Ipv6Addr::from(octets);
            TargetAddr::Ip(SocketAddr::from((
                ip,
                u16::from_be_bytes([buf[16], buf[17]]),
            )))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact(client, &mut len).await?;
            let mut buf = vec![0u8; usize::from(len[0]) + 2];
            read_exact(client, &mut buf).await?;
            let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
            buf.truncate(buf.len() - 2);
            let domain =
                String::from_utf8(buf).map_err(|_| invalid("socks5 domain is not utf-8"))?;
            if domain.is_empty() {
                return Err(invalid("socks5 domain is empty"));
            }
            TargetAddr::Domain(domain, port)
        }
        _ => {
            client.write_all(&reply(REP_ADDRESS_NOT_SUPPORTED)).await?;
            return Err(invalid("unsupported socks5 address type"));
        }
    };
    Ok(Request {
        target,
        initial: Vec::new(),
        reply: Reply::Socks5,
    })
}

async fn authenticate(client: &mut TcpStream, expected: &Credentials) -> io::Result<()> {
    let mut head = [0u8; 2];
    read_exact(client, &mut head).await?;
    if head[0] != AUTH_VERSION {
        return Err(invalid("bad socks5 auth version"));
    }
    let mut username = vec![0u8; usize::from(head[1])];
    read_exact(client, &mut username).await?;
    let mut len = [0u8; 1];
    read_exact(client, &mut len).await?;
    let mut password = vec![0u8; usize::from(len[0])];
    read_exact(client, &mut password).await?;
    let ok = username == expected.username.as_bytes() && password == expected.password.as_bytes();
    client
        .write_all(&[AUTH_VERSION, if ok { 0x00 } else { 0x01 }])
        .await?;
    if ok {
        Ok(())
    } else {
        Err(invalid("socks5 authentication failed"))
    }
}
