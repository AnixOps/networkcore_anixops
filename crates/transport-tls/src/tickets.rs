//! Where the client keeps what it needs to resume TLS sessions.
//!
//! rustls's own memory cache keeps 8 TLS 1.3 tickets per server. A proxy
//! client dials the same server for every connection, and a page load opens
//! dozens at once: with 8 tickets, everything past the eighth connection of
//! a burst pays a full handshake. This store keeps [`TICKETS_PER_SERVER`]
//! per server, newest last, for up to [`MAX_SERVERS`] servers (the server
//! added first goes when a new one would pass that). Each ticket is handed
//! out once, as TLS 1.3 asks of clients (RFC 8446 §C.4): a ticket used twice
//! would link the two connections for an observer.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use rustls::client::{ClientSessionStore, Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::pki_types::ServerName;
use rustls::NamedGroup;

/// TLS 1.3 tickets kept per server.
pub const TICKETS_PER_SERVER: usize = 64;
/// Servers remembered at once.
pub const MAX_SERVERS: usize = 64;

#[derive(Default)]
struct ServerData {
    kx_hint: Option<NamedGroup>,
    tls12: Option<Tls12ClientSessionValue>,
    /// Oldest first.
    tls13: VecDeque<Tls13ClientSessionValue>,
}

#[derive(Default)]
struct Servers {
    data: HashMap<ServerName<'static>, ServerData>,
    /// Insertion order, for eviction.
    order: VecDeque<ServerName<'static>>,
}

impl Servers {
    fn entry(&mut self, name: ServerName<'static>) -> &mut ServerData {
        if !self.data.contains_key(&name) {
            while self.data.len() >= MAX_SERVERS {
                match self.order.pop_front() {
                    Some(oldest) => {
                        self.data.remove(&oldest);
                    }
                    None => break,
                }
            }
            self.order.push_back(name.clone());
        }
        self.data.entry(name).or_default()
    }
}

/// A [`ClientSessionStore`] with room for bursts of connections.
#[derive(Default)]
pub struct TicketStore {
    servers: Mutex<Servers>,
}

impl TicketStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Servers> {
        self.servers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// TLS 1.3 tickets held for `name`.
    pub fn tickets(&self, name: &ServerName<'_>) -> usize {
        self.lock()
            .data
            .get(&name.to_owned())
            .map_or(0, |data| data.tls13.len())
    }
}

impl fmt::Debug for TicketStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketStore")
            .field("servers", &self.lock().data.len())
            .finish()
    }
}

impl ClientSessionStore for TicketStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.lock().entry(server_name).kx_hint = Some(group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.lock()
            .data
            .get(&server_name.to_owned())
            .and_then(|data| data.kx_hint)
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.lock().entry(server_name).tls12 = Some(value);
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.lock()
            .data
            .get(&server_name.to_owned())
            .and_then(|data| data.tls12.clone())
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        if let Some(data) = self.lock().data.get_mut(server_name) {
            data.tls12 = None;
        }
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        let mut servers = self.lock();
        let tickets = &mut servers.entry(server_name).tls13;
        if tickets.len() >= TICKETS_PER_SERVER {
            tickets.pop_front();
        }
        tickets.push_back(value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        // Newest first: it has the most lifetime left.
        self.lock()
            .data
            .get_mut(server_name)
            .and_then(|data| data.tls13.pop_back())
    }
}
