//! `$persistentStore` backends.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const SCRIPT_STORE_MAX_KEY_BYTES: usize = 256;
pub const SCRIPT_STORE_MAX_VALUE_BYTES: usize = 512 * 1024;
pub const SCRIPT_STORE_MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;

/// Key-value storage shared by all scripts of one runtime, as in Loon.
pub trait ScriptStore: Send + Sync {
    fn read(&self, key: &str) -> Option<String>;
    /// Returns `false` when the write is refused (size limits) or not durable.
    fn write(&self, key: &str, value: &str) -> bool;
    fn remove(&self, key: &str) -> bool;
}

fn write_allowed(entries: &BTreeMap<String, String>, key: &str, value: &str) -> bool {
    if key.is_empty()
        || key.len() > SCRIPT_STORE_MAX_KEY_BYTES
        || value.len() > SCRIPT_STORE_MAX_VALUE_BYTES
    {
        return false;
    }
    let total = entries
        .iter()
        .filter(|(existing, _)| existing.as_str() != key)
        .map(|(existing, existing_value)| existing.len() + existing_value.len())
        .sum::<usize>();
    total + key.len() + value.len() <= SCRIPT_STORE_MAX_TOTAL_BYTES
}

/// In-memory store, used by tests and when no store path is configured.
#[derive(Debug, Default)]
pub struct MemoryScriptStore {
    entries: Mutex<BTreeMap<String, String>>,
}

impl MemoryScriptStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_entries(entries: BTreeMap<String, String>) -> Self {
        Self {
            entries: Mutex::new(entries),
        }
    }

    pub fn snapshot(&self) -> BTreeMap<String, String> {
        self.entries
            .lock()
            .map(|entries| entries.clone())
            .unwrap_or_default()
    }
}

impl ScriptStore for MemoryScriptStore {
    fn read(&self, key: &str) -> Option<String> {
        self.entries.lock().ok()?.get(key).cloned()
    }

    fn write(&self, key: &str, value: &str) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        if !write_allowed(&entries, key, value) {
            return false;
        }
        entries.insert(key.to_string(), value.to_string());
        true
    }

    fn remove(&self, key: &str) -> bool {
        self.entries
            .lock()
            .map(|mut entries| entries.remove(key).is_some())
            .unwrap_or(false)
    }
}

/// Store persisted as one JSON object. Every successful write replaces the
/// file through a temporary sibling, so a crash never leaves partial JSON.
#[derive(Debug)]
pub struct JsonFileScriptStore {
    path: PathBuf,
    entries: Mutex<BTreeMap<String, String>>,
}

impl JsonFileScriptStore {
    /// Opens `path`. A missing file is an empty store; a file that is not a
    /// JSON object of strings is an error, so it is never overwritten.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let entries = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<BTreeMap<String, String>>(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self, entries: &BTreeMap<String, String>) -> bool {
        let Ok(json) = serde_json::to_vec(entries) else {
            return false;
        };
        let mut temporary = self.path.clone().into_os_string();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        if std::fs::write(&temporary, json).is_err() {
            return false;
        }
        if std::fs::rename(&temporary, &self.path).is_err() {
            let _ = std::fs::remove_file(&temporary);
            return false;
        }
        true
    }
}

impl ScriptStore for JsonFileScriptStore {
    fn read(&self, key: &str) -> Option<String> {
        self.entries.lock().ok()?.get(key).cloned()
    }

    fn write(&self, key: &str, value: &str) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        if !write_allowed(&entries, key, value) {
            return false;
        }
        let previous = entries.insert(key.to_string(), value.to_string());
        if self.persist(&entries) {
            return true;
        }
        match previous {
            Some(previous) => entries.insert(key.to_string(), previous),
            None => entries.remove(key),
        };
        false
    }

    fn remove(&self, key: &str) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        let Some(previous) = entries.remove(key) else {
            return false;
        };
        if self.persist(&entries) {
            return true;
        }
        entries.insert(key.to_string(), previous);
        false
    }
}
