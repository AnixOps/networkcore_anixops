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
use engine_embedded::profile::{self, RoutingMode, RuleList};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    pub script_runtime_configured: bool,
    pub dark_theme: bool,
    pub runtime_mode: &'static str,
    pub routing_mode: &'static str,
    /// Always true: the interface then offers the subscription rules mode and explains the engine's DNS.
    pub embedded_engine: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSummary {
    pub id: String,
    pub label: String,
    pub protocol: String,
    pub selected: bool,
}

/// A policy group in the interface's `NativeGroupSummary` shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupSummary {
    pub tag: String,
    /// `selector`, `urltest` or `fallback`, as the interface labels them.
    pub group_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected: Option<String>,
    pub outbounds: Vec<String>,
    pub outbound_labels: Vec<String>,
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
    Ok(OperationResult {
        message: message.into(),
    })
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
    /// The selected source's envelope with every node, rules and policy groups, when it has them.
    routed_profile: Option<String>,
    desktop: Option<Desktop>,
    autostart_dir: Option<PathBuf>,
    executable: PathBuf,
    last_error: Option<String>,
    configuration_error: Option<String>,
}

impl Backend {
    /// Loads the saved state and first puts back proxy settings a previous run left changed.
    pub fn open(
        store: Store,
        desktop: Option<Desktop>,
        autostart_dir: Option<PathBuf>,
        executable: PathBuf,
    ) -> Self {
        let state = store.load();
        let mut backend = Self {
            store,
            state,
            engine: Engine::default(),
            nodes: Vec::new(),
            routed_profile: None,
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
        self.routed_profile = None;
        self.configuration_error = None;
        let Some(source) = self.state.selected_source() else {
            return;
        };
        match self
            .store
            .read_source(&source.id)
            .map_err(|error| error.to_string())
            .and_then(|content| engine::parse_nodes(&content).map(|nodes| (content, nodes)))
        {
            Ok((content, nodes)) => {
                self.routed_profile = engine::subscription_routing(&content, &nodes);
                self.nodes = nodes;
            }
            Err(error) => self.configuration_error = Some(error),
        }
    }

    /// The selected source's routed profile with the saved group choices, if it has rules and groups.
    fn routed(&self) -> Option<Value> {
        let mut profile: Value = serde_json::from_str(self.routed_profile.as_deref()?).ok()?;
        for (group, member) in &self.state.group_choices {
            // A choice the subscription no longer offers is skipped.
            let _ = profile::set_group_default(&mut profile, group, member);
        }
        Some(profile)
    }

    /// The node traffic goes to: FINAL's node in a routed profile, else the chosen node.
    fn current_node_id(&self) -> Option<String> {
        match self.routed() {
            Some(profile) => profile::selected_node(&profile),
            None => engine::choose_node(&self.nodes, self.state.selected_node.as_deref())
                .map(|node| node.id.clone()),
        }
    }

    /// The envelope to run: the profile (routed, or the chosen node) in the routing mode.
    fn envelope(&self) -> Result<String, String> {
        let profile = match self.routed() {
            Some(profile) => profile.to_string(),
            None => {
                let node = engine::choose_node(&self.nodes, self.state.selected_node.as_deref())
                    .ok_or(
                        "import a subscription with a node the embedded engine supports first",
                    )?;
                engine::envelope(&self.nodes, &node.id)?
            }
        };
        profile::envelope_for_mode(&profile, self.state.routing_mode, |list| {
            self.store.read_rule_list(list).ok_or_else(|| {
                "the routing rules have not been downloaded yet; refresh them on the Rules page"
                    .to_string()
            })
        })
    }

    /// Public rule lists the routing mode needs: the missing ones, or all of them with `force`. The window
    /// downloads them outside the lock and saves them with `store()`.
    pub fn rule_lists_to_download(&self, mode: RoutingMode, force: bool) -> Vec<RuleList> {
        mode.rule_lists()
            .iter()
            .copied()
            .filter(|list| force || !self.store.has_rule_list(*list))
            .collect()
    }

    pub fn store(&self) -> Store {
        self.store.clone()
    }

    pub fn routing_mode(&self) -> RoutingMode {
        self.state.routing_mode
    }

    /// Starts (or restarts) the engine on the current envelope and returns what it routes through.
    fn launch(&mut self) -> Result<(String, std::net::SocketAddr), String> {
        let envelope = self.envelope()?;
        let node_id = self.current_node_id().unwrap_or_default();
        let address = self
            .engine
            .start(&envelope, &node_id, self.state.listen_port)?;
        let label =
            if self.routed_profile.is_some() && self.state.routing_mode != RoutingMode::Direct {
                "the subscription's policy groups".to_string()
            } else if self.state.routing_mode == RoutingMode::Direct {
                "direct connections".to_string()
            } else {
                self.node_name(&node_id).unwrap_or(node_id)
            };
        Ok((label, address))
    }

    /// Restarts a running engine so a changed choice takes effect. Returns whether it was running.
    fn restart_if_running(&mut self) -> Result<bool, String> {
        if !self.engine.is_running() {
            return Ok(false);
        }
        self.launch()?;
        Ok(true)
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
                    || {
                        "this desktop is not supported; set applications to the local proxy by hand"
                            .to_string()
                    },
                    |address| format!("set applications to {address} by hand"),
                )),
                "warning",
            ),
            (Some(desktop), Some(_)) => {
                StatusFact::new("Enabled", Some(desktop.name().to_string()), "success")
            }
            (Some(desktop), None) => {
                StatusFact::new("Disabled", Some(desktop.name().to_string()), "neutral")
            }
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
        RuntimeSnapshot {
            platform: "linux",
            connection: connection.to_string(),
            connection_label: connection.to_string(),
            service: StatusFact::new("Not used", None, "neutral"),
            core: if running {
                StatusFact::new(
                    "Running",
                    self.engine.address().map(|address| address.to_string()),
                    "success",
                )
            } else {
                StatusFact::new("Stopped", None, if crashed { "danger" } else { "neutral" })
            },
            proxy: self.proxy_fact(),
            selected_node: self.current_node_id(),
            subscription: source.map(|source| source.location.clone()),
            subscription_last_updated: source
                .and_then(|source| source.last_success)
                .map(format_time),
            subscription_last_attempt: source
                .and_then(|source| source.last_attempt)
                .map(format_time),
            subscription_next_attempt: None,
            subscription_refresh_result: String::new(),
            subscription_added_node_count: 0,
            subscription_removed_node_count: 0,
            subscription_changed_node_count: 0,
            subscription_refresh_error_code: None,
            subscription_error: source.and_then(|source| source.last_error.clone()),
            last_error: self.last_error.clone(),
            configuration_error: self.configuration_error.clone(),
            start_after_login: self
                .autostart_dir
                .as_deref()
                .is_some_and(autostart::is_enabled),
            auto_connect: self.state.preferences.auto_connect,
            auto_recover_core: false,
            auto_subscription_refresh: false,
            auto_select_fastest_node: false,
            bilibili_web_ad_block_enabled: false,
            script_runtime_configured: false,
            dark_theme: false,
            runtime_mode: "desktop",
            routing_mode: self.state.routing_mode.as_str(),
            embedded_engine: true,
        }
    }

    pub fn nodes(&self) -> Vec<NodeSummary> {
        let selected = self.current_node_id();
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

    /// The routed profile's policy groups, members labelled with node names.
    pub fn groups(&self) -> Vec<GroupSummary> {
        let Some(profile) = self.routed() else {
            return Vec::new();
        };
        profile::groups(&profile)
            .into_iter()
            .map(|group| GroupSummary {
                tag: group.id,
                group_type: match group.kind.as_str() {
                    "select" => "selector".to_string(),
                    "url-test" => "urltest".to_string(),
                    other => other.to_string(),
                },
                selected: group.choice,
                outbound_labels: group
                    .members
                    .iter()
                    .map(|member| self.node_name(member).unwrap_or_else(|| member.clone()))
                    .collect(),
                outbounds: group.members,
            })
            .collect()
    }

    /// Picks `member` for the select group `group`; a running engine restarts on it.
    pub fn select_group_member(
        &mut self,
        group: &str,
        member: &str,
    ) -> Result<OperationResult, String> {
        let mut profile = self
            .routed()
            .ok_or("the current subscription has no policy groups")?;
        profile::set_group_default(&mut profile, group, member)?;
        self.state
            .group_choices
            .insert(group.to_string(), member.to_string());
        self.save();
        let label = self.node_name(member).unwrap_or_else(|| member.to_string());
        if self.restart_if_running()? {
            done(format!(
                "Policy group {group} now uses {label}; reconnected"
            ))
        } else {
            done(format!("Policy group {group} now uses {label}"))
        }
    }

    /// Switches the routing mode; its rule lists must already be downloaded. A running engine restarts on it.
    pub fn set_routing_mode(&mut self, mode: RoutingMode) -> Result<OperationResult, String> {
        if !self.rule_lists_to_download(mode, false).is_empty() {
            return Err("the routing rules for this mode could not be downloaded".to_string());
        }
        let previous = self.state.routing_mode;
        self.state.routing_mode = mode;
        if let Err(error) = self.restart_if_running() {
            self.state.routing_mode = previous;
            return Err(error);
        }
        self.save();
        done(format!("Routing mode set to {}", mode.as_str()))
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
                result: if source.last_error.is_some() {
                    "failed"
                } else {
                    "succeeded"
                }
                .to_string(),
                added_node_count: 0,
                removed_node_count: 0,
                changed_node_count: 0,
                error_code: None,
                last_update_error: source.last_error.clone(),
            })
            .collect()
    }

    /// Records why a connection could not start before the engine was reached.
    pub fn record_error(&mut self, error: &str) {
        self.last_error = Some(error.to_string());
    }

    pub fn connect(&mut self) -> Result<OperationResult, String> {
        let result = self.start();
        self.last_error = result.as_ref().err().cloned();
        result
    }

    fn start(&mut self) -> Result<OperationResult, String> {
        let (label, address) = self.launch()?;
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
        done(format!("Connected through {label} on {address}"))
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
                Err(error) => {
                    self.last_error =
                        Some(format!("the system proxy could not be restored: {error}"))
                }
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
        // In a routed profile a node switch picks the node in the main select group.
        if let Some(profile) = self.routed() {
            let group = profile::switch_group_for_node(&profile, &node.id).ok_or(
                "the policy groups choose this subscription's nodes; switch them on the Rules page",
            )?;
            return self.select_group_member(&group, &node.id);
        }
        self.state.selected_node = Some(node.id.clone());
        self.save();
        self.restart_if_running()?;
        done(format!("Switched to {}", node.name))
    }

    /// The current nodes, for delay tests run outside the lock.
    pub fn node_list(&self) -> Vec<NodeDescriptor> {
        self.nodes.clone()
    }

    pub fn node_name(&self, node_id: &str) -> Option<String> {
        self.nodes
            .iter()
            .find(|node| node.id == node_id)
            .map(|node| node.name.clone())
    }

    /// Saves a newly fetched source. `content` is the URL's body, the file, or the pasted links.
    pub fn import(&mut self, location: &str, content: &str) -> Result<OperationResult, String> {
        let nodes = engine::parse_nodes(content)?;
        let supported = nodes
            .iter()
            .filter(|node| engine::is_supported(node))
            .count();
        if supported == 0 {
            return Err("none of the nodes can run on the embedded engine yet".to_string());
        }
        let id = self.state.add_source(location, now());
        if let Err(error) = self.store.write_source(&id, content) {
            self.state.remove_source(&id);
            return Err(format!("the subscription could not be saved: {error}"));
        }
        self.state.selected_node = None;
        self.state.group_choices.clear();
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
    pub fn finish_refresh(
        &mut self,
        id: &str,
        fetched: Result<String, String>,
    ) -> Result<OperationResult, String> {
        let time = now();
        let parsed =
            fetched.and_then(|content| engine::parse_nodes(&content).map(|nodes| (content, nodes)));
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
        self.state.group_choices.clear();
        self.save();
        self.reload_nodes();
        done("Subscription selected; reconnect to use it")
    }

    pub fn remove_subscription(&mut self, id: &str) -> Result<OperationResult, String> {
        let was_selected = self
            .state
            .selected_source()
            .is_some_and(|source| source.id == id);
        if !self.state.remove_source(id) {
            return Err("the subscription was not found".to_string());
        }
        if was_selected {
            self.state.group_choices.clear();
        }
        self.store.remove_source(id);
        self.save();
        self.reload_nodes();
        done("Subscription removed")
    }

    pub fn save_preferences(
        &mut self,
        input: &PreferencesInput,
    ) -> Result<OperationResult, String> {
        if let Some(dir) = &self.autostart_dir {
            if autostart::is_enabled(dir) != input.start_after_login {
                autostart::set_enabled(dir, input.start_after_login, &self.executable).map_err(
                    |error| format!("the autostart entry could not be changed: {error}"),
                )?;
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
        let supported = self
            .nodes
            .iter()
            .filter(|node| engine::is_supported(node))
            .count();
        if supported == 0 {
            return Err("no node the embedded engine can run".to_string());
        }
        done(format!(
            "{supported} of {} nodes can run on the embedded engine",
            self.nodes.len()
        ))
    }

    /// Writes a report without node addresses, names or credentials.
    pub fn diagnostics(&self) -> Result<OperationResult, String> {
        let snapshot = self.snapshot();
        let mut protocols: Vec<String> = self
            .nodes
            .iter()
            .map(|node| engine::protocol_name(&node.protocol))
            .collect();
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// `YYYY-MM-DD HH:MM UTC` from Unix seconds.
pub fn format_time(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let minutes = (seconds % 86_400) / 60;
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        minutes / 60,
        minutes % 60
    )
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
        let dir =
            std::env::temp_dir().join(format!("anixops-net-backend-{name}-{}", std::process::id()));
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
        assert!(
            json.get("connectionLabel").is_some(),
            "fields use the interface's camelCase names"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    const CLASH: &str = r#"
proxies:
  - name: HK
    type: ss
    server: 82.47.34.99
    port: 11111
    cipher: aes-256-gcm
    password: f43c0eee-13b9-4f07-bec9-d4b744141503
  - name: JP
    type: ss
    server: 82.47.34.100
    port: 11112
    cipher: aes-256-gcm
    password: f43c0eee-13b9-4f07-bec9-d4b744141504
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Auto
      - HK
      - DIRECT
  - name: Auto
    type: url-test
    proxies:
      - JP
      - HK
    url: http://www.gstatic.com/generate_204
    interval: 300
rules:
  - DOMAIN-SUFFIX,example.org,DIRECT
  - MATCH,Proxy
"#;

    #[test]
    fn subscription_rules_route_and_policy_groups_switch() {
        let (mut backend, dir) = backend("routed");
        backend.import("https://example.com/sub", CLASH).unwrap();
        let groups = backend.groups();
        assert_eq!(
            groups
                .iter()
                .map(|group| group.tag.as_str())
                .collect::<Vec<_>>(),
            ["Proxy", "Auto"]
        );
        assert_eq!(groups[0].group_type, "selector");
        assert_eq!(groups[0].selected.as_deref(), Some("Auto"));
        assert_eq!(groups[1].group_type, "urltest");
        assert!(groups[1].outbound_labels.contains(&"JP".to_string()));
        let hk = backend
            .node_list()
            .into_iter()
            .find(|node| node.name == "HK")
            .unwrap()
            .id;
        let jp = groups[1].outbounds[0].clone();
        assert_eq!(
            backend.snapshot().selected_node.as_deref(),
            Some(jp.as_str())
        );

        // A node switch picks the node in the main select group, and the choice is saved.
        backend.switch_node(&hk).unwrap();
        assert_eq!(backend.groups()[0].selected.as_deref(), Some(hk.as_str()));
        assert_eq!(
            backend.snapshot().selected_node.as_deref(),
            Some(hk.as_str())
        );
        assert!(backend.select_group_member("Auto", &hk).is_err());
        backend.select_group_member("Proxy", "DIRECT").unwrap();
        assert_eq!(backend.snapshot().selected_node, None);
        let routed: serde_json::Value = serde_json::from_str(&backend.envelope().unwrap()).unwrap();
        assert_eq!(routed["routing"]["groups"][0]["default"], "DIRECT");

        // List modes need their downloaded lists; direct and rule modes need none.
        assert_eq!(backend.snapshot().routing_mode, "rule");
        assert!(backend.set_routing_mode(RoutingMode::BypassChina).is_err());
        assert_eq!(
            backend.rule_lists_to_download(RoutingMode::BypassChina, false),
            [RuleList::ChinaDomains, RuleList::ChinaIps]
        );
        let store = backend.store();
        store
            .write_rule_list(RuleList::ChinaDomains, &["cn".to_string()])
            .unwrap();
        store
            .write_rule_list(RuleList::ChinaIps, &["1.0.1.0/24".to_string()])
            .unwrap();
        assert!(backend
            .rule_lists_to_download(RoutingMode::BypassChina, false)
            .is_empty());
        backend.set_routing_mode(RoutingMode::BypassChina).unwrap();
        let bypass: serde_json::Value = serde_json::from_str(&backend.envelope().unwrap()).unwrap();
        assert_eq!(bypass["routing"]["rules"][0], "RULE-SET,china,DIRECT");
        assert_eq!(
            bypass["routing"]["rule_sets"]["china"]["domain_suffix"][0],
            "cn"
        );
        backend.set_routing_mode(RoutingMode::Direct).unwrap();
        assert_eq!(backend.snapshot().routing_mode, "direct");

        // Choices belong to the subscription they were made in.
        let _ = backend.import(PASTED_LOCATION, LINK);
        assert!(backend.state.group_choices.is_empty());
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
                assert!(
                    backend.refreshable_location().is_none(),
                    "pasted links cannot be refetched"
                );
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
