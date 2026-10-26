//! The user table of one inbound: credentials, traffic counters and online
//! connections.
//!
//! Users are keyed by `name`, which the node agent chooses (anix-agent uses
//! one name per panel user). A protocol inbound looks users up by its own
//! credential through a [`UserIndex`], which is rebuilt lazily whenever the
//! table changes.
//!
//! Removing a user revokes it: connections that are still open are closed by
//! the serve loop, and traffic not yet collected is kept until the next
//! [`UserStore::traffic`] call so a panel does not lose billed bytes.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::net::IpAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::registry::BuildError;

/// One user as configured. Which credential fields apply depends on the
/// protocol: Shadowsocks and Trojan use `password`, VLESS and VMess use
/// `uuid`, TUIC uses both, iWAN uses `username` (or `name`), `password` and
/// optionally `address`. Has no `Debug` on purpose.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// VLESS flow, e.g. `xtls-rprx-vision`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// Login name for protocols whose clients type one in (iWAN); `name`
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Fixed tunnel address for layer-3 protocols (iWAN); assigned from the
    /// inbound's pool when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<IpAddr>,
}

impl User {
    pub fn with_password(name: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            password: Some(password.into()),
            uuid: None,
            flow: None,
            username: None,
            address: None,
        }
    }

    pub fn with_uuid(name: impl Into<String>, uuid: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            password: None,
            uuid: Some(uuid.into()),
            flow: None,
            username: None,
            address: None,
        }
    }
}

/// Bytes charged to one user since the last reset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserTraffic {
    pub name: String,
    /// Client to server.
    pub up: u64,
    /// Server to client.
    pub down: u64,
}

/// One remote IP with open connections for a user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnlineUser {
    pub name: String,
    pub ip: IpAddr,
    pub connections: u32,
}

/// A user plus its live counters. Shared by the store, the protocol index and
/// every open connection of the user.
pub struct UserEntry {
    user: User,
    up: AtomicU64,
    down: AtomicU64,
    online: Mutex<HashMap<IpAddr, u32>>,
    revoked: AtomicBool,
    revoke: Notify,
}

impl UserEntry {
    fn new(user: User) -> Self {
        Self {
            user,
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            online: Mutex::new(HashMap::new()),
            revoked: AtomicBool::new(false),
            revoke: Notify::new(),
        }
    }

    pub fn user(&self) -> &User {
        &self.user
    }

    pub fn name(&self) -> &str {
        &self.user.name
    }

    pub fn add_up(&self, bytes: u64) {
        self.up.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_down(&self, bytes: u64) {
        self.down.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Current `(up, down)` without resetting.
    pub fn traffic(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }

    fn take_traffic(&self) -> (u64, u64) {
        (
            self.up.swap(0, Ordering::Relaxed),
            self.down.swap(0, Ordering::Relaxed),
        )
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    /// Completes once the user has been removed or replaced.
    pub async fn revoked(&self) {
        loop {
            let mut notified = pin!(self.revoke.notified());
            notified.as_mut().enable();
            if self.is_revoked() {
                return;
            }
            notified.await;
        }
    }

    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
        self.revoke.notify_waiters();
    }

    /// Marks one connection from `ip` as online until the guard drops.
    pub fn connect(self: &Arc<Self>, ip: IpAddr) -> OnlineGuard {
        let mut online = self.online.lock().unwrap_or_else(|e| e.into_inner());
        *online.entry(ip).or_insert(0) += 1;
        OnlineGuard {
            entry: self.clone(),
            ip,
        }
    }

    fn online(&self) -> Vec<(IpAddr, u32)> {
        let online = self.online.lock().unwrap_or_else(|e| e.into_inner());
        online.iter().map(|(ip, count)| (*ip, *count)).collect()
    }
}

/// Keeps one connection counted as online.
pub struct OnlineGuard {
    entry: Arc<UserEntry>,
    ip: IpAddr,
}

impl Drop for OnlineGuard {
    fn drop(&mut self) {
        let mut online = self.entry.online.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = online.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                online.remove(&self.ip);
            }
        }
    }
}

/// Checks a user's credentials for one protocol before it is stored.
pub type Validator = Box<dyn Fn(&User) -> Result<(), BuildError> + Send + Sync>;

#[derive(Default)]
struct Table {
    users: BTreeMap<String, Arc<UserEntry>>,
    /// Bumped on every change; indexes compare it to their cached copy.
    generation: u64,
    /// Uncollected traffic of removed or replaced users.
    retired: BTreeMap<String, (u64, u64)>,
}

/// The users of one inbound.
pub struct UserStore {
    table: RwLock<Table>,
    validator: Option<Validator>,
}

impl Default for UserStore {
    fn default() -> Self {
        Self::new(None)
    }
}

impl UserStore {
    pub fn new(validator: Option<Validator>) -> Self {
        Self {
            table: RwLock::new(Table::default()),
            validator,
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Table> {
        self.table.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Table> {
        self.table.write().unwrap_or_else(|e| e.into_inner())
    }

    fn check(&self, user: &User) -> Result<(), BuildError> {
        if user.name.is_empty() {
            return Err("user name is empty");
        }
        match &self.validator {
            Some(validate) => validate(user),
            None => Ok(()),
        }
    }

    /// Adds `user`, or replaces the user with the same name. Replacing with
    /// different credentials revokes the old entry and closes its
    /// connections; replacing with identical settings changes nothing.
    pub fn add(&self, user: User) -> Result<(), BuildError> {
        self.check(&user)?;
        let mut table = self.write();
        if let Some(existing) = table.users.get(&user.name) {
            if existing.user == user {
                return Ok(());
            }
        }
        let name = user.name.clone();
        let old = table.users.insert(name, Arc::new(UserEntry::new(user)));
        if let Some(old) = old {
            retire(&mut table, &old);
        }
        table.generation += 1;
        Ok(())
    }

    /// Adds every user, or none if any is invalid or two share a name.
    pub fn add_all(&self, users: Vec<User>) -> Result<(), BuildError> {
        let mut names = std::collections::HashSet::new();
        for user in &users {
            self.check(user)?;
            if !names.insert(user.name.as_str()) {
                return Err("user names must be unique");
            }
        }
        for user in users {
            self.add(user)?;
        }
        Ok(())
    }

    /// Removes the user and closes its connections. Returns whether it existed.
    pub fn remove(&self, name: &str) -> bool {
        let mut table = self.write();
        match table.users.remove(name) {
            Some(old) => {
                retire(&mut table, &old);
                table.generation += 1;
                true
            }
            None => false,
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<UserEntry>> {
        self.read().users.get(name).cloned()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.read().users.contains_key(name)
    }

    pub fn len(&self) -> usize {
        self.read().users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.read().users.is_empty()
    }

    /// User names in sorted order.
    pub fn names(&self) -> Vec<String> {
        self.read().users.keys().cloned().collect()
    }

    pub fn generation(&self) -> u64 {
        self.read().generation
    }

    /// The current entries and the generation they belong to.
    pub fn snapshot(&self) -> (u64, Vec<Arc<UserEntry>>) {
        let table = self.read();
        (table.generation, table.users.values().cloned().collect())
    }

    /// Traffic per user with at least one byte, sorted by name. With `reset`
    /// the counters restart from zero, so each byte is reported once.
    pub fn traffic(&self, reset: bool) -> Vec<UserTraffic> {
        let mut totals: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        if reset {
            let mut table = self.write();
            totals = std::mem::take(&mut table.retired);
            for (name, entry) in &table.users {
                add_totals(&mut totals, name, entry.take_traffic());
            }
        } else {
            let table = self.read();
            totals.clone_from(&table.retired);
            for (name, entry) in &table.users {
                add_totals(&mut totals, name, entry.traffic());
            }
        }
        totals
            .into_iter()
            .map(|(name, (up, down))| UserTraffic { name, up, down })
            .collect()
    }

    /// Every (user, IP) pair with an open connection, sorted.
    pub fn online(&self) -> Vec<OnlineUser> {
        let table = self.read();
        let mut out = Vec::new();
        for (name, entry) in &table.users {
            let mut ips = entry.online();
            ips.sort();
            out.extend(ips.into_iter().map(|(ip, connections)| OnlineUser {
                name: name.clone(),
                ip,
                connections,
            }));
        }
        out
    }
}

fn retire(table: &mut Table, old: &Arc<UserEntry>) {
    old.revoke();
    let name = old.name().to_owned();
    add_totals(&mut table.retired, &name, old.take_traffic());
}

fn add_totals(totals: &mut BTreeMap<String, (u64, u64)>, name: &str, (up, down): (u64, u64)) {
    if up == 0 && down == 0 {
        return;
    }
    let total = totals.entry(name.to_owned()).or_insert((0, 0));
    total.0 += up;
    total.1 += down;
}

type IndexMap<K> = Arc<HashMap<K, Arc<UserEntry>>>;

/// Lookup from a protocol credential to the user, cached per store
/// generation.
pub struct UserIndex<K> {
    store: Arc<UserStore>,
    key: fn(&User) -> Option<K>,
    cache: Mutex<(u64, IndexMap<K>)>,
}

impl<K: Eq + Hash> UserIndex<K> {
    /// `key` derives the lookup key from a user; users for which it returns
    /// `None` are not reachable through the index.
    pub fn new(store: Arc<UserStore>, key: fn(&User) -> Option<K>) -> Self {
        Self {
            store,
            key,
            cache: Mutex::new((u64::MAX, Arc::new(HashMap::new()))),
        }
    }

    pub fn store(&self) -> &Arc<UserStore> {
        &self.store
    }

    pub fn get(&self, key: &K) -> Option<Arc<UserEntry>> {
        self.current().get(key).cloned()
    }

    fn current(&self) -> IndexMap<K> {
        let generation = self.store.generation();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.0 != generation {
            let (generation, entries) = self.store.snapshot();
            let map = entries
                .into_iter()
                .filter_map(|entry| (self.key)(entry.user()).map(|key| (key, entry)))
                .collect();
            *cache = (generation, Arc::new(map));
        }
        cache.1.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn store() -> Arc<UserStore> {
        Arc::new(UserStore::new(Some(Box::new(|user: &User| {
            match user.password.as_deref() {
                Some(password) if !password.is_empty() => Ok(()),
                _ => Err("user password is missing"),
            }
        }))))
    }

    #[test]
    fn add_validates_and_replaces() {
        let store = store();
        assert!(store.add(User::with_password("", "x")).is_err());
        assert!(store.add(User::with_uuid("a", "u")).is_err());
        store.add(User::with_password("a", "one")).unwrap();
        let first = store.get("a").unwrap();
        let generation = store.generation();

        store.add(User::with_password("a", "one")).unwrap();
        assert_eq!(store.generation(), generation, "identical add is a no-op");
        assert!(!first.is_revoked());

        store.add(User::with_password("a", "two")).unwrap();
        assert!(first.is_revoked());
        assert_eq!(store.len(), 1);
        assert_eq!(
            store.get("a").unwrap().user().password.as_deref(),
            Some("two")
        );
    }

    #[test]
    fn add_all_is_atomic() {
        let store = store();
        let users = vec![User::with_password("a", "1"), User::with_password("a", "2")];
        assert_eq!(store.add_all(users), Err("user names must be unique"));
        assert!(store.is_empty());
    }

    #[test]
    fn traffic_survives_removal_until_collected() {
        let store = store();
        store.add(User::with_password("a", "1")).unwrap();
        store.add(User::with_password("b", "2")).unwrap();
        store.get("a").unwrap().add_up(10);
        store.get("a").unwrap().add_down(20);
        store.get("b").unwrap().add_down(5);

        assert_eq!(store.traffic(false).len(), 2);
        assert!(store.remove("a"));
        assert!(!store.remove("a"));
        let traffic = store.traffic(true);
        assert_eq!(
            traffic,
            vec![
                UserTraffic {
                    name: "a".into(),
                    up: 10,
                    down: 20
                },
                UserTraffic {
                    name: "b".into(),
                    up: 0,
                    down: 5
                },
            ]
        );
        assert!(store.traffic(true).is_empty());
    }

    #[test]
    fn online_counts_connections_per_ip() {
        let store = store();
        store.add(User::with_password("a", "1")).unwrap();
        let entry = store.get("a").unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let first = entry.connect(ip);
        let second = entry.connect(ip);
        assert_eq!(
            store.online(),
            vec![OnlineUser {
                name: "a".into(),
                ip,
                connections: 2
            }]
        );
        drop(first);
        drop(second);
        assert!(store.online().is_empty());
    }

    #[test]
    fn index_follows_changes() {
        let store = store();
        let index = UserIndex::new(store.clone(), |user: &User| user.password.clone());
        store.add(User::with_password("a", "1")).unwrap();
        assert_eq!(index.get(&"1".to_owned()).unwrap().name(), "a");
        store.add(User::with_password("a", "2")).unwrap();
        assert!(index.get(&"1".to_owned()).is_none());
        assert!(index.get(&"2".to_owned()).is_some());
        store.remove("a");
        assert!(index.get(&"2".to_owned()).is_none());
    }

    #[tokio::test]
    async fn revoked_wakes_waiters() {
        let store = store();
        store.add(User::with_password("a", "1")).unwrap();
        let entry = store.get("a").unwrap();
        let waiter = tokio::spawn({
            let entry = entry.clone();
            async move { entry.revoked().await }
        });
        tokio::task::yield_now().await;
        store.remove("a");
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("revocation should wake the waiter")
            .unwrap();
    }
}
