//! Socket protection: keeps the engine's own sockets off a packet tunnel.
//!
//! When the host routes the whole system into a TUN adapter (Windows TUN
//! mode), every socket the engine opens to a proxy server, a DNS upstream or
//! a direct destination would also be routed into that adapter and loop back
//! into the engine. The host installs a [`SocketProtector`] that pins such a
//! socket to the physical interface (on Windows, `IP_UNICAST_IF`), like
//! `VpnService.protect` on Android.
//!
//! The protector is process-wide: every socket opened through
//! [`connect_tcp`], [`connect_tcp_host`], [`bind_udp`] or [`bind_std_udp`]
//! passes through it before it connects or sends. Without a protector these
//! helpers are plain socket calls. Loopback destinations are never handed to
//! the protector.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// The operating system handle of a socket.
#[cfg(windows)]
pub type RawSocketHandle = std::os::windows::io::RawSocket;
/// The operating system handle of a socket.
#[cfg(unix)]
pub type RawSocketHandle = std::os::fd::RawFd;
/// The operating system handle of a socket.
#[cfg(not(any(windows, unix)))]
pub type RawSocketHandle = i64;

/// Pins a socket the engine opened to a path outside the packet tunnel.
///
/// Called once per socket, before it connects or sends, with the address it
/// is about to reach. An error fails that connection instead of letting it
/// loop through the tunnel.
pub trait SocketProtector: Send + Sync {
    fn protect(&self, socket: RawSocketHandle, target: SocketAddr) -> io::Result<()>;
}

impl<F> SocketProtector for F
where
    F: Fn(RawSocketHandle, SocketAddr) -> io::Result<()> + Send + Sync,
{
    fn protect(&self, socket: RawSocketHandle, target: SocketAddr) -> io::Result<()> {
        self(socket, target)
    }
}

static PROTECTOR: RwLock<Option<Arc<dyn SocketProtector>>> = RwLock::new(None);

/// Installs (or with `None`, removes) the process-wide protector.
pub fn set_socket_protector(protector: Option<Arc<dyn SocketProtector>>) {
    let mut slot = PROTECTOR
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = protector;
}

/// Whether a protector is installed.
pub fn socket_protector_installed() -> bool {
    current().is_some()
}

fn current() -> Option<Arc<dyn SocketProtector>> {
    PROTECTOR
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn protect(socket: RawSocketHandle, target: SocketAddr) -> io::Result<()> {
    if target.ip().is_loopback() {
        return Ok(());
    }
    match current() {
        Some(protector) => protector.protect(socket, target),
        None => Ok(()),
    }
}

#[cfg(windows)]
fn raw<S: std::os::windows::io::AsRawSocket>(socket: &S) -> RawSocketHandle {
    socket.as_raw_socket()
}

#[cfg(unix)]
fn raw<S: std::os::fd::AsRawFd>(socket: &S) -> RawSocketHandle {
    socket.as_raw_fd()
}

/// The unspecified address of `target`'s family, port 0.
pub fn unspecified_for(target: SocketAddr) -> SocketAddr {
    if target.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    }
}

/// A TCP connection to `target`, protected first.
pub async fn connect_tcp(target: SocketAddr) -> io::Result<TcpStream> {
    if current().is_none() {
        return TcpStream::connect(target).await;
    }
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    #[cfg(any(windows, unix))]
    protect(raw(&socket), target)?;
    socket.connect(target).await
}

/// A TCP connection to `host:port`: each resolved address in turn, like
/// [`TcpStream::connect`], every attempt protected.
pub async fn connect_tcp_host(host: &str, port: u16) -> io::Result<TcpStream> {
    if current().is_none() {
        return TcpStream::connect((host, port)).await;
    }
    let mut last_error = None;
    for address in tokio::net::lookup_host((host, port)).await? {
        match connect_tcp(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "host did not resolve to an address",
        )
    }))
}

/// A blocking-API UDP socket bound to `local`, protected for `target`, in
/// non-blocking mode (ready for tokio or quinn). It is not connected.
pub fn bind_std_udp(local: SocketAddr, target: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(local)?;
    #[cfg(any(windows, unix))]
    protect(raw(&socket), target)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// A tokio UDP socket on the unspecified address of `target`'s family,
/// protected for `target`. It is not connected.
pub fn bind_udp(target: SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::from_std(bind_std_udp(unspecified_for(target), target)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    // The protector is process-wide; tests that install one run one at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn protector_sees_remote_sockets_but_not_loopback() {
        let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        set_socket_protector(Some(Arc::new(
            move |_socket: RawSocketHandle, target: SocketAddr| {
                assert!(!target.ip().is_loopback());
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )));
        assert!(socket_protector_installed());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        connect_tcp(address).await.unwrap();
        accept.await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // A documentation address: the socket is protected, nothing is sent.
        let remote: SocketAddr = "192.0.2.1:9".parse().unwrap();
        bind_udp(remote).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        set_socket_protector(None);
        assert!(!socket_protector_installed());
        bind_udp(remote).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failing_protector_fails_the_socket() {
        let _guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        set_socket_protector(Some(Arc::new(
            |_socket: RawSocketHandle, _target: SocketAddr| {
                Err(io::Error::other("no physical interface"))
            },
        )));
        let remote: SocketAddr = "192.0.2.1:9".parse().unwrap();
        assert!(bind_udp(remote).is_err());
        set_socket_protector(None);
    }
}
