//! The tunnel address pool of one inbound (spec §12.2).
//!
//! The first usable address of the network is the node's own end of the
//! tunnel (the gateway, also the DNS address); users get the others. A user
//! keeps its address across reconnects: a released address stays reserved
//! for its user for [`RECLAIM_AFTER`]. Fixed addresses set by the panel are
//! never handed out dynamically, and a user that logs in with its fixed
//! address takes it from whoever holds it.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// A released address stays reserved for its user this long.
pub const RECLAIM_AFTER: Duration = Duration::from_secs(600);
/// Candidates tried at most when looking for a free address.
const MAX_PROBES: u32 = 1 << 20;

/// An IPv4 network of prefix length 8 to 30.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    base: u32,
    prefix: u8,
}

impl Network {
    /// Parses `10.66.0.0/16`; host bits are ignored.
    pub fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.split_once('/')?;
        let address: Ipv4Addr = address.trim().parse().ok()?;
        let prefix: u8 = prefix.trim().parse().ok()?;
        if !(8..=30).contains(&prefix) {
            return None;
        }
        Some(Self {
            base: u32::from(address) & mask(prefix),
            prefix,
        })
    }

    pub fn contains(&self, address: Ipv4Addr) -> bool {
        u32::from(address) & mask(self.prefix) == self.base
    }

    /// The node's own address in the tunnel.
    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base + 1)
    }

    /// Whether `address` can belong to a user: inside the network, not the
    /// network, gateway or broadcast address.
    pub fn assignable(&self, address: Ipv4Addr) -> bool {
        let value = u32::from(address);
        self.contains(address) && value > self.base + 1 && value < self.broadcast()
    }

    fn broadcast(&self) -> u32 {
        self.base | !mask(self.prefix)
    }

    fn first(&self) -> u32 {
        self.base + 2
    }
}

fn mask(prefix: u8) -> u32 {
    u32::MAX << (32 - u32::from(prefix))
}

struct Lease {
    address: Ipv4Addr,
    /// When its session ended; `None` while one is open.
    released: Option<Instant>,
}

pub struct Pool {
    network: Network,
    /// By user name.
    leases: HashMap<String, Lease>,
    holders: HashMap<Ipv4Addr, String>,
    cursor: u32,
}

impl Pool {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            leases: HashMap::new(),
            holders: HashMap::new(),
            cursor: network.first(),
        }
    }

    /// Gives `user` an address: `fixed` when set, else the address it had
    /// last, else a free one that `reserved` (someone's fixed address) does
    /// not claim. Also returns the user that held a fixed address before; its
    /// session must end. `None` when the pool is exhausted.
    pub fn acquire(
        &mut self,
        user: &str,
        fixed: Option<Ipv4Addr>,
        reserved: impl Fn(Ipv4Addr) -> bool,
        now: Instant,
    ) -> Option<(Ipv4Addr, Option<String>)> {
        self.expire(now);
        if let Some(fixed) = fixed {
            if !self.network.assignable(fixed) {
                return None;
            }
            let evicted = self
                .holders
                .get(&fixed)
                .filter(|holder| holder.as_str() != user)
                .cloned();
            if let Some(holder) = &evicted {
                self.leases.remove(holder);
            }
            self.assign(user, fixed);
            return Some((fixed, evicted));
        }
        if let Some(lease) = self.leases.get(user) {
            let address = lease.address;
            // An address that became someone's fixed one is given up.
            if !reserved(address) {
                self.assign(user, address);
                return Some((address, None));
            }
        }
        let first = self.network.first();
        let span = self.network.broadcast() - first;
        for _ in 0..span.min(MAX_PROBES) {
            let candidate = Ipv4Addr::from(self.cursor);
            self.cursor = if self.cursor + 1 >= self.network.broadcast() {
                first
            } else {
                self.cursor + 1
            };
            if self.holders.contains_key(&candidate) || reserved(candidate) {
                continue;
            }
            self.assign(user, candidate);
            return Some((candidate, None));
        }
        None
    }

    /// Marks the address of `user` as unused from `now`.
    pub fn release(&mut self, user: &str, now: Instant) {
        if let Some(lease) = self.leases.get_mut(user) {
            lease.released.get_or_insert(now);
        }
    }

    /// Frees addresses released at least [`RECLAIM_AFTER`] ago.
    pub fn expire(&mut self, now: Instant) {
        let holders = &mut self.holders;
        self.leases.retain(|_, lease| match lease.released {
            Some(released) if now.saturating_duration_since(released) >= RECLAIM_AFTER => {
                holders.remove(&lease.address);
                false
            }
            _ => true,
        });
    }

    fn assign(&mut self, user: &str, address: Ipv4Addr) {
        let previous = self.leases.insert(
            user.to_owned(),
            Lease {
                address,
                released: None,
            },
        );
        if let Some(previous) = previous {
            if previous.address != address {
                self.holders.remove(&previous.address);
            }
        }
        self.holders.insert(address, user.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(network: &str) -> Pool {
        Pool::new(Network::parse(network).unwrap())
    }

    fn none(_: Ipv4Addr) -> bool {
        false
    }

    #[test]
    fn parses_networks() {
        let network = Network::parse("10.66.1.7/16").unwrap();
        assert_eq!(network.gateway(), Ipv4Addr::new(10, 66, 0, 1));
        assert!(network.contains(Ipv4Addr::new(10, 66, 255, 255)));
        assert!(!network.contains(Ipv4Addr::new(10, 67, 0, 1)));
        assert!(network.assignable(Ipv4Addr::new(10, 66, 0, 2)));
        assert!(!network.assignable(Ipv4Addr::new(10, 66, 0, 0)));
        assert!(!network.assignable(Ipv4Addr::new(10, 66, 0, 1)));
        assert!(!network.assignable(Ipv4Addr::new(10, 66, 255, 255)));
        for bad in [
            "10.66.0.0",
            "10.66.0.0/31",
            "10.66.0.0/7",
            "10.66.0/16",
            "x/16",
        ] {
            assert!(Network::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn users_keep_their_address_until_it_is_reclaimed() {
        let mut pool = pool("10.0.0.0/29");
        let now = Instant::now();
        let (a, _) = pool.acquire("a", None, none, now).unwrap();
        let (b, _) = pool.acquire("b", None, none, now).unwrap();
        assert_eq!(a, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(b, Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(pool.acquire("a", None, none, now).unwrap().0, a);

        pool.release("a", now);
        let later = now + RECLAIM_AFTER / 2;
        assert_eq!(pool.acquire("a", None, none, later).unwrap().0, a);
        pool.release("a", later);
        // Still reserved for "a" while others come and go.
        for user in ["c", "d", "e"] {
            assert_ne!(pool.acquire(user, None, none, later).unwrap().0, a);
        }
        // 10.0.0.2-6 are the only user addresses of a /29: full now.
        assert!(pool.acquire("f", None, none, later).is_none());
        let reclaimed = later + RECLAIM_AFTER;
        assert_eq!(pool.acquire("f", None, none, reclaimed).unwrap().0, a);
    }

    #[test]
    fn fixed_addresses_are_never_dynamic_and_win() {
        let mut pool = pool("10.0.0.0/24");
        let now = Instant::now();
        let fixed = Ipv4Addr::new(10, 0, 0, 2);
        let reserved = |address: Ipv4Addr| address == fixed;
        let (dynamic, _) = pool.acquire("a", None, reserved, now).unwrap();
        assert_eq!(dynamic, Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(
            pool.acquire("b", Some(fixed), reserved, now).unwrap(),
            (fixed, None)
        );
        // A fixed address taken by someone else moves to its owner.
        let (taken, _) = pool.acquire("c", None, none, now).unwrap();
        assert_eq!(
            pool.acquire("d", Some(taken), none, now).unwrap(),
            (taken, Some("c".to_owned()))
        );
        assert_ne!(pool.acquire("c", None, none, now).unwrap().0, taken);
        assert!(pool
            .acquire("e", Some(Ipv4Addr::new(10, 0, 0, 1)), none, now)
            .is_none());
    }
}
