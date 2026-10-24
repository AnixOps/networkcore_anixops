//! What the client keeps between runs: subscription sources and their cached content, the selected node,
//! preferences and the system proxy settings to restore. Everything lives under
//! `$XDG_CONFIG_HOME/anixops-net` (or `~/.config/anixops-net`); files that can hold node credentials are
//! written owner-only.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::system_proxy::ProxyBackup;

pub const DEFAULT_LISTEN_PORT: u16 = 7890;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SavedState {
    pub sources: Vec<SavedSource>,
    pub selected_node: Option<String>,
    pub preferences: Preferences,
    pub listen_port: u16,
    /// Set while the client has changed the desktop's proxy settings; cleared once they are restored.
    pub proxy_backup: Option<ProxyBackup>,
    next_source: u32,
}

impl Default for SavedState {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            selected_node: None,
            preferences: Preferences::default(),
            listen_port: DEFAULT_LISTEN_PORT,
            proxy_backup: None,
            next_source: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    pub start_after_login: bool,
    pub auto_connect: bool,
    /// Point the desktop's proxy settings at the local proxy while connected.
    pub system_proxy: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            start_after_login: false,
            auto_connect: false,
            system_proxy: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedSource {
    pub id: String,
    /// The URL or file path, or "粘贴的节点" for links pasted directly.
    pub location: String,
    pub selected: bool,
    pub last_success: Option<u64>,
    pub last_attempt: Option<u64>,
    pub last_error: Option<String>,
}

impl SavedSource {
    pub fn refreshable(&self) -> bool {
        self.location.starts_with("https://") || self.location.starts_with("http://")
    }
}

impl SavedState {
    pub fn selected_source(&self) -> Option<&SavedSource> {
        self.sources.iter().find(|source| source.selected)
    }

    /// Adds a source and selects it. Returns its id.
    pub fn add_source(&mut self, location: &str, now: u64) -> String {
        let id = format!("s{}", self.next_source.max(1));
        self.next_source = self.next_source.max(1) + 1;
        for source in &mut self.sources {
            source.selected = false;
        }
        self.sources.push(SavedSource {
            id: id.clone(),
            location: location.to_string(),
            selected: true,
            last_success: Some(now),
            last_attempt: Some(now),
            last_error: None,
        });
        id
    }

    /// Selects `id`; returns false when there is no such source.
    pub fn select_source(&mut self, id: &str) -> bool {
        if !self.sources.iter().any(|source| source.id == id) {
            return false;
        }
        for source in &mut self.sources {
            source.selected = source.id == id;
        }
        true
    }

    /// Removes `id`; the first remaining source becomes selected if the removed one was.
    pub fn remove_source(&mut self, id: &str) -> bool {
        let Some(index) = self.sources.iter().position(|source| source.id == id) else {
            return false;
        };
        let removed = self.sources.remove(index);
        if removed.selected {
            if let Some(first) = self.sources.first_mut() {
                first.selected = true;
            }
        }
        true
    }
}

/// Reads and writes the state file and the cached subscription contents.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// `$XDG_CONFIG_HOME/anixops-net`, else `~/.config/anixops-net`.
    pub fn default_dir() -> Option<PathBuf> {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
        Some(config.join("anixops-net"))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn load(&self) -> SavedState {
        fs::read(self.dir.join("state.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, state: &SavedState) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
        self.write_private("state.json", &bytes)
    }

    pub fn read_source(&self, id: &str) -> io::Result<String> {
        fs::read_to_string(self.source_path(id))
    }

    pub fn write_source(&self, id: &str, content: &str) -> io::Result<()> {
        self.write_private(&format!("sources/{id}.txt"), content.as_bytes())
    }

    pub fn remove_source(&self, id: &str) {
        let _ = fs::remove_file(self.source_path(id));
    }

    pub fn write_report(&self, name: &str, content: &str) -> io::Result<PathBuf> {
        self.write_private(name, content.as_bytes())?;
        Ok(self.dir.join(name))
    }

    fn source_path(&self, id: &str) -> PathBuf {
        self.dir.join("sources").join(format!("{id}.txt"))
    }

    /// Writes through a temporary file and a rename, owner-only.
    fn write_private(&self, relative: &str, bytes: &[u8]) -> io::Result<()> {
        let path = self.dir.join(relative);
        let parent = path.parent().unwrap_or(&self.dir);
        fs::create_dir_all(parent)?;
        let temporary = path.with_extension("tmp");
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        fs::rename(&temporary, &path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("anixops-net-state-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn sources_keep_one_selection() {
        let mut state = SavedState::default();
        let first = state.add_source("https://example.com/a", 1);
        let second = state.add_source("https://example.com/b", 2);
        assert_eq!(
            state.selected_source().map(|source| source.id.as_str()),
            Some(second.as_str())
        );
        assert!(state.select_source(&first));
        assert_eq!(
            state
                .sources
                .iter()
                .filter(|source| source.selected)
                .count(),
            1
        );
        assert!(state.remove_source(&first));
        assert_eq!(
            state.selected_source().map(|source| source.id.as_str()),
            Some(second.as_str())
        );
        assert!(!state.select_source("missing"));
        let third = state.add_source("ss://example", 3);
        assert_ne!(third, first, "ids are never reused");
    }

    #[test]
    fn state_round_trips_and_defaults_missing_fields() {
        let dir = temp_dir("roundtrip");
        let store = Store::new(dir.clone());
        assert_eq!(store.load(), SavedState::default());

        let mut state = SavedState::default();
        state.add_source("https://example.com/sub", 10);
        state.selected_node = Some("node-1".to_string());
        store.save(&state).unwrap();
        store.write_source("s1", "ss://secret").unwrap();
        assert_eq!(store.load(), state);
        assert_eq!(store.read_source("s1").unwrap(), "ss://secret");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("sources/s1.txt"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "cached subscriptions are owner-only");
        }

        fs::write(dir.join("state.json"), br#"{"listen_port": 1080}"#).unwrap();
        let partial = store.load();
        assert_eq!(partial.listen_port, 1080);
        assert!(partial.preferences.system_proxy);
        let _ = fs::remove_dir_all(dir);
    }
}
