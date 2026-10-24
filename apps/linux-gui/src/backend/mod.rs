//! Everything behind the window, free of Tauri so the workspace can test it: saved state, the embedded engine,
//! the desktop's proxy settings and the autostart entry. The window layer (`app.rs`) only moves values in and
//! out and does network fetches and delay tests outside the lock.

pub mod autostart;
pub mod engine;
pub mod state;
pub mod system_proxy;

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use control_domain::NodeDescriptor;
use serde::{Deserialize, Serialize};

use self::engine::Engine;
use self::state::{SavedState, Store};
use self::system_proxy::Desktop;

/// The source label for share links pasted into the import field.
pub const PASTED_LOCATION: &str = "粘贴的链接";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusFact {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub tone: &'static str,
}

impl StatusFact {
    fn new(label: &str, detail: Option<String>, tone: &'static str) -> Self {
        Self {
            label: label.to_string(),
            detail,
            tone,
        }
    }
}

/// The interface's `RuntimeSnapshot`; Windows-only facts get fixed values and `platform` lets the interface
/// hide what does not apply.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSnapshot {
    pub platform: &'static str,
    pub connection: String,
    pub connection_label: String,
    pub service: StatusFact,
    pub core: StatusFact,
    pub proxy: StatusFact,
    pub selected_node: Option<String>,
    pub subscription: Option<String>,
    pub subscription_last_updated: Option<String>,
    pub subscription_last_attempt: Option<String>,
    pub subscription_next_attempt: Option<String>,
    pub subscription_refresh_result: String,
    pub subscription_added_node_count: u32,
    pub subscription_removed_node_count: u32,
    pub subscription_changed_node_count: u32,
    pub subscription_refresh_error_code: Option<String>,
    pub subscription_error: Option<String>,
    pub last_error: Option<String>,
    pub configuration_error: Option<String>,
    pub start_after_login: bool,
    pub auto_connect: bool,
    pub auto_recover_core: bool,
    pub auto_subscription_refresh: bool,
    pub auto_select_fastest_node: bool,
    pub bilibili_web_ad_block_enabled: bool,
    pub dns_configured: bool,
    pub script_runtime_configured: bool,
    pub dark_theme: bool,
    pub runtime_mode: &'static str,
    pub routing_mode: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSummary {
    pub id: String,
    pub label: String,
    pub protocol: String,
    pub selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionSummary {
    pub id: String,
    pub location: String,
    pub selected: bool,
    pub last_successful_update: Option<String>,
    pub last_attempt: Option<String>,
    pub next_attempt: Option<String>,
    pub result: String,
    pub added_node_count: u32,
    pub removed_node_count: u32,
    pub changed_node_count: u32,
    pub error_code: Option<String>,
    pub last_update_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationResult {
    pub message: String,
}

fn done(message: impl Into<String>) -> Result<OperationResult, String> {
    Ok(OperationResult { message: message.into() })
}

/// The preferences the interface saves; fields Linux does not use are ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferencesInput {
    pub start_after_login: bool,
    pub auto_connect: bool,
}

pub struct Backend {
    store: Store,
    state: SavedState,
    engine: Engine,
    /// Nodes of the selected source.
    nodes: Vec<NodeDescriptor>,
    desktop: Option<Desktop>,
    autostart_dir: Option<PathBuf>,
    executable: PathBuf,
    last_error: Option<String>,
    configuration_error: Option<String>,
}

impl Backend {
    /// Loads the saved state and first puts back proxy settings a previous run left changed.
    pub fn open(store: Store, desktop: Option<Desktop>, autostart_dir: Option<PathBuf>, executable: PathBuf) -> Self {
        let state = store.load();
        let mut backend = Self {
            store,
            state,
            engine: Engine::default(),
            nodes: Vec::new(),
            desktop,
            autostart_dir,
            executable,
            last_error: None,
            configuration_error: None,
        };
        backend.restore_proxy();
        backend.reload_nodes();
        backend
    }

    pub fn auto_connect(&self) -> bool {
        self.state.preferences.auto_connect
    }

    fn save(&mut self) {
        if let Err(error) = self.store.save(&self.state) {
            self.last_error = Some(format!("settings could not be saved: {error}"));
        }
    }

    fn reload_nodes(&mut self) {
        self.nodes.clear();
        self.configuration_error = None;
        let Some(source) = self.state.selected_source() else {
            return;
        };
        match self.store.read_source(&source.id).map_err(|error| error.to_string()).and_then(|content| engine::parse_nodes(&content)) {
            Ok(nodes) => self.nodes = nodes,
            Err(error) => self.configuration_error = Some(error),
        }
    }

    fn proxy_fact(&self) -> StatusFact {
        let address = self.engine.address().map(|address| address.to_string());
        if !self.state.preferences.system_proxy {
            return StatusFact::new("Not used", address, "neutral");
        }
        match (self.desktop, &self.state.proxy_backup) {
            (None, _) => StatusFact::new(
                "Unavailable",
                Some(address.map_or_else(
                    || "this desktop is not supported; set applications to the local proxy by hand".to_string(),
                    |address| format!("set applications to {address} by hand"),
                )),
                "warning",
            ),
            (Some(desktop), Some(_)) => StatusFact::new("Enabled", Some(desktop.name().to_string()), "success"),
            (Some(desktop), None) => StatusFact::new("Disabled", Some(desktop.name().to_string()), "neutral"),
        }
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        let running = self.engine.is_running();
        let crashed = !running && self.engine.node_id().is_some();
        let connection = if running {
            "Connected"
        } else if crashed {
            "Core error"
        } else if self.last_error.is_some() {
            "Connection failed"
        } else {
            "Not connected"
        };
        let source = self.state.selected_source();
        let selected = engine::choose_node(&self.nodes, self.state.selected_node.as_deref());
        RuntimeSnapshot {
            platform: "linux",
            connection: connection.to_string(),
            connection_label: connection.to_string(),
            service: StatusFact::new("Not used", None, "neutral"),
            core: if running {
                StatusFact::new("Running", self.engine.address().map(|address| address.to_string()), "success")
            } else {
                StatusFact::new("Stopped", None, if crashed { "danger" } else { "neutral" })
            },
            proxy: self.proxy_fact(),
            selected_node: selected.map(|node| node.id.clone()),
            subscription: source.map(|source| source.location.clone()),
            subscription_last_updated: source.and_then(|source| source.last_success).map(format_time),
            subscription_last_attempt: source.and_then(|source| source.last_attempt).map(format_time),
            subscription_next_attempt: None,
            subscription_refresh_result: String::new(),
            subscription_added_node_count: 0,
            subscription_removed_node_count: 0,
            subscription_changed_node_count: 0,
            subscription_refresh_error_code: None,
            subscription_error: source.and_then(|source| source.last_error.clone()),
            last_error: self.last_error.clone(),
            configuration_error: self.configuration_error.clone(),
            start_after_login: self.autostart_dir.as_deref().is_some_and(autostart::is_enabled),
            auto_connect: self.state.preferences.auto_connect,
            auto_recover_core: false,
            auto_subscription_refresh: false,
            auto_select_fastest_node: false,
            bilibili_web_ad_block_enabled: false,
            dns_configured: false,
            script_runtime_configured: false,
            dark_theme: false,
            runtime_mode: "desktop",
            routing_mode: "bypass_china",
        }
    }

    pub fn nodes(&self) -> Vec<NodeSummary> {
        let selected = engine::choose_node(&self.nodes, self.state.selected_node.as_deref()).map(|node| node.id.clone());
        self.nodes
            .iter()
            .filter(|node| engine::is_supported(node))
            .map(|node| NodeSummary {
                id: node.id.clone(),
                label: node.name.clone(),
                protocol: engine::protocol_name(&node.protocol),
                selected: selected.as_deref() == Some(node.id.as_str()),
            })
            .collect()
    }

    pub fn subscriptions(&self) -> Vec<SubscriptionSummary> {
        self.state
            .sources
            .iter()
            .map(|source| SubscriptionSummary {
                id: source.id.clone(),
                location: source.location.clone(),
                selected: source.selected,
                last_successful_update: source.last_success.map(format_time),
                last_attempt: source.last_attempt.map(format_time),
                next_attempt: None,
                result: if source.last_error.is_some() { "failed" } else { "succeeded" }.to_string(),
                added_node_count: 0,
                removed_node_count: 0,
                changed_node_count: 0,
                error_code: None,
                last_update_error: source.last_error.clone(),
            })
            .collect()
    }

    pub fn connect(&mut self) -> Result<OperationResult, String> {
        let result = self.start();
        self.last_error = result.as_ref().err().cloned();
        result
    }

    fn start(&mut self) -> Result<OperationResult, String> {
        let node = engine::choose_node(&self.nodes, self.state.selected_node.as_deref())
            .ok_or("import a subscription with a node the embedded engine supports first")?
            .clone();
        let envelope = engine::envelope(&self.nodes, &node.id)?;
        let address = self.engine.start(&envelope, &node.id, self.state.listen_port)?;
        if self.state.preferences.system_proxy && self.state.proxy_backup.is_none() {
            if let Some(desktop) = self.desktop {
                match system_proxy::apply(desktop, address.port()) {
                    Ok(backup) => {
                        self.state.proxy_backup = Some(backup);
                        self.save();
                    }
                    Err(error) => {
                        self.engine.stop();
                        return Err(format!("the system proxy could not be set: {error}"));
                    }
                }
            }
        }
        done(format!("Connected through {} on {address}", node.name))
    }

    pub fn disconnect(&mut self) -> Result<OperationResult, String> {
        self.engine.stop();
        self.last_error = None;
        self.restore_proxy();
        done("Disconnected")
    }

    fn restore_proxy(&mut self) {
        if let Some(backup) = self.state.proxy_backup.clone() {
            match system_proxy::restore(&backup) {
                Ok(()) => {
                    self.state.proxy_backup = None;
                    self.save();
                }
                Err(error) => self.last_error = Some(format!("the system proxy could not be restored: {error}")),
            }
        }
    }

    pub fn restore_network_settings(&mut self) -> Result<OperationResult, String> {
        if self.state.proxy_backup.is_none() {
            return done("The system proxy settings are not changed by this app");
        }
        self.restore_proxy();
        match &self.last_error {
            Some(error) if self.state.proxy_backup.is_some() => Err(error.clone()),
            _ => done("System proxy settings restored"),
        }
    }

    /// Stops the engine and puts the proxy settings back; called when the window closes.
    pub fn shutdown(&mut self) {
        self.engine.stop();
        self.restore_proxy();
    }

    pub fn switch_node(&mut self, node_id: &str) -> Result<OperationResult, String> {
        let node = self
            .nodes
            .iter()
            .find(|node| node.id == node_id && engine::is_supported(node))
            .ok_or("the node is not in the current subscription")?
            .clone();
        self.state.selected_node = Some(node.id.clone());
        self.save();
        if self.engine.is_running() {
            let envelope = engine::envelope(&self.nodes, &node.id)?;
            self.engine.start(&envelope, &node.id, self.state.listen_port)?;
        }
        done(format!("Switched to {}", node.name))
    }

    /// The current nodes, for delay tests run outside the lock.
    pub fn node_list(&self) -> Vec<NodeDescriptor> {
        self.nodes.clone()
    }

    pub fn node_name(&self, node_id: &str) -> Option<String> {
        self.nodes.iter().find(|node| node.id == node_id).map(|node| node.name.clone())
    }

    /// Saves a newly fetched source. `content` is the URL's body, the file, or the pasted links.
    pub fn import(&mut self, location: &str, content: &str) -> Result<OperationResult, String> {
        let nodes = engine::parse_nodes(content)?;
        let supported = nodes.iter().filter(|node| engine::is_supported(node)).count();
        if supported == 0 {
            return Err("none of the nodes can run on the embedded engine yet".to_string());
        }
        let id = self.state.add_source(location, now());
        if let Err(error) = self.store.write_source(&id, content) {
            self.state.remove_source(&id);
            return Err(format!("the subscription could not be saved: {error}"));
        }
        self.state.selected_node = None;
        self.save();
        self.reload_nodes();
        done(format!("Imported {supported} of {} nodes", nodes.len()))
    }

    /// The selected source's URL when it can be fetched again.
    pub fn refreshable_location(&self) -> Option<(String, String)> {
        self.state
            .selected_source()
            .filter(|source| source.refreshable())
            .map(|source| (source.id.clone(), source.location.clone()))
    }

    /// Records a refresh of source `id`: the new content, or why it failed.
    pub fn finish_refresh(&mut self, id: &str, fetched: Result<String, String>) -> Result<OperationResult, String> {
        let time = now();
        let parsed = fetched.and_then(|content| engine::parse_nodes(&content).map(|nodes| (content, nodes)));
        let result = match parsed {
            Ok((content, nodes)) => self
                .store
                .write_source(id, &content)
                .map(|()| nodes.len())
                .map_err(|error| format!("the subscription could not be saved: {error}")),
            Err(error) => Err(error),
        };
        if let Some(source) = self.state.sources.iter_mut().find(|source| source.id == id) {
            source.last_attempt = Some(time);
            match &result {
                Ok(_) => {
                    source.last_success = Some(time);
                    source.last_error = None;
                }
                Err(error) => source.last_error = Some(error.clone()),
            }
        }
        self.save();
        self.reload_nodes();
        result.map(|count| OperationResult {
            message: format!("Subscription updated: {count} nodes"),
        })
    }

    pub fn select_subscription(&mut self, id: &str) -> Result<OperationResult, String> {
        if !self.state.select_source(id) {
            return Err("the subscription was not found".to_string());
        }
        self.state.selected_node = None;
        self.save();
        self.reload_nodes();
        done("Subscription selected; reconnect to use it")
    }

    pub fn remove_subscription(&mut self, id: &str) -> Result<OperationResult, String> {
        if !self.state.remove_source(id) {
            return Err("the subscription was not found".to_string());
        }
        self.store.remove_source(id);
        self.save();
        self.reload_nodes();
        done("Subscription removed")
    }

    pub fn save_preferences(&mut self, input: &PreferencesInput) -> Result<OperationResult, String> {
        if let Some(dir) = &self.autostart_dir {
            if autostart::is_enabled(dir) != input.start_after_login {
                autostart::set_enabled(dir, input.start_after_login, &self.executable)
                    .map_err(|error| format!("the autostart entry could not be changed: {error}"))?;
            }
        }
        self.state.preferences.auto_connect = input.auto_connect;
        self.save();
        done("Settings saved")
    }

    pub fn validate(&self) -> Result<OperationResult, String> {
        if let Some(error) = &self.configuration_error {
            return Err(error.clone());
        }
        let supported = self.nodes.iter().filter(|node| engine::is_supported(node)).count();
        if supported == 0 {
            return Err("no node the embedded engine can run".to_string());
        }
        done(format!("{supported} of {} nodes can run on the embedded engine", self.nodes.len()))
    }

    /// Writes a report without node addresses, names or credentials.
    pub fn diagnostics(&self) -> Result<OperationResult, String> {
        let snapshot = self.snapshot();
        let mut protocols: Vec<String> = self.nodes.iter().map(|node| engine::protocol_name(&node.protocol)).collect();
        protocols.sort();
        protocols.dedup();
        let report = format!(
            "AnixOps Net (Linux) {}\nconnection: {}\ncore: {}\nsystem proxy: {} ({})\ndesktop: {}\nsources: {}\nnodes: {} ({} supported)\nprotocols: {}\nlast error: {}\nconfiguration error: {}\n",
            env!("CARGO_PKG_VERSION"),
            snapshot.connection,
            snapshot.core.label,
            snapshot.proxy.label,
            snapshot.proxy.detail.as_deref().unwrap_or("-"),
            self.desktop.map_or("unsupported", Desktop::name),
            self.state.sources.len(),
            self.nodes.len(),
            self.nodes.iter().filter(|node| engine::is_supported(node)).count(),
            protocols.join(", "),
            snapshot.last_error.as_deref().unwrap_or("none"),
            snapshot.configuration_error.as_deref().unwrap_or("none"),
        );
        let path = self
            .store
            .write_report(&format!("diagnostics-{}.txt", now()), &report)
            .map_err(|error| format!("the report could not be written: {error}"))?;
        done(format!("Diagnostics report saved to {}", path.display()))
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

/// `YYYY-MM-DD HH:MM UTC` from Unix seconds.
pub fn format_time(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let minutes = (seconds % 86_400) / 60;
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02} UTC", minutes / 60, minutes % 60)
}

/// How long a delay result reads in a message.
pub fn format_delay(delay: Duration) -> String {
    format!("{} ms", delay.as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#HK";

    fn backend(name: &str) -> (Backend, PathBuf) {
        let dir = std::env::temp_dir().join(format!("anixops-net-backend-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let backend = Backend::open(
            Store::new(dir.join("config")),
            None,
            Some(dir.join("autostart")),
            PathBuf::from("/usr/bin/anixops-net"),
        );
        (backend, dir)
    }

    #[test]
    fn formats_utc_times() {
        assert_eq!(format_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_time(1_761_300_000), "2025-10-24 10:00 UTC");
        assert_eq!(format_delay(Duration::from_millis(123)), "123 ms");
    }

    #[test]
    fn a_fresh_backend_is_disconnected_and_linux() {
        let (backend, dir) = backend("fresh");
        let snapshot = backend.snapshot();
        assert_eq!(snapshot.platform, "linux");
        assert_eq!(snapshot.connection, "Not connected");
        assert_eq!(snapshot.proxy.label, "Unavailable");
        assert!(backend.nodes().is_empty());
        let json = serde_json::to_value(&snapshot).unwrap();
        assert!(json.get("connectionLabel").is_some(), "fields use the interface's camelCase names");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn importing_selects_the_source_and_preferences_write_autostart() {
        let (mut backend, dir) = backend("import");
        assert!(backend.import(PASTED_LOCATION, "nothing useful").is_err());
        match backend.import(PASTED_LOCATION, LINK) {
            Ok(result) => {
                assert!(result.message.starts_with("Imported 1 of 1"));
                assert_eq!(backend.subscriptions().len(), 1);
                assert_eq!(backend.nodes().len(), 1);
                assert!(backend.nodes()[0].selected);
                assert!(backend.validate().is_ok());
                assert!(backend.refreshable_location().is_none(), "pasted links cannot be refetched");
                let id = backend.subscriptions()[0].id.clone();
                assert!(backend.remove_subscription(&id).is_ok());
                assert!(backend.nodes().is_empty());
            }
            // Only when this build's engine lacks the node's cipher.
            Err(error) => assert!(error.contains("embedded engine")),
        }

        backend
            .save_preferences(&PreferencesInput {
                start_after_login: true,
                auto_connect: true,
            })
            .unwrap();
        assert!(backend.snapshot().start_after_login);
        assert!(backend.auto_connect());
        let _ = std::fs::remove_dir_all(dir);
    }
}
