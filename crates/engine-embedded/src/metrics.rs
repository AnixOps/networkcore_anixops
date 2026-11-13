//! Engine metrics in the Prometheus text exposition format (version 0.0.4).
//!
//! The client serves this text on a loopback port on the desktop and puts it
//! in the diagnostics export on iOS and macOS; it reaches both through the
//! `metrics` control command. Written by hand: the format is a few lines of
//! text and the engine takes no metrics library.
//!
//! Every value is a counter or gauge of the engine itself: traffic, connection
//! counts and results, the routing mode, policy groups and rule sets. Hosts,
//! addresses, processes and outbound settings never appear. Policy group,
//! member and rule set names do, unless the request asks for anonymous
//! labels, which replace them with their position (`group_1`, `member_2`).

use std::fmt::Write;

use crate::connections::{Dispatcher, Mode, Network};

/// The `Content-Type` of [`render`]'s text.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// How names from the user's profile appear in labels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Labels {
    /// Group, member and rule set names as the profile has them.
    #[default]
    Named,
    /// Positions instead of names, for text that leaves the device.
    Anonymous,
}

/// The metrics of the engine running `dispatcher`.
pub fn render(dispatcher: &Dispatcher, labels: Labels) -> String {
    let mut out = Text::default();
    let tracker = dispatcher.tracker();
    let traffic = tracker.traffic();
    let counters = tracker.counters();

    out.family(
        "networkcore_build_info",
        "gauge",
        "Engine version; always 1.",
    );
    out.sample(
        "networkcore_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );
    out.family(
        "networkcore_uptime_seconds",
        "gauge",
        "Seconds since the engine started.",
    );
    out.sample_f64(
        "networkcore_uptime_seconds",
        &[],
        counters.uptime.as_secs_f64(),
    );

    out.family(
        "networkcore_mode",
        "gauge",
        "Routing mode; 1 for the current one.",
    );
    let mode = dispatcher.mode();
    for (name, value) in [
        ("rule", Mode::Rule),
        ("global", Mode::Global),
        ("direct", Mode::Direct),
    ] {
        out.sample(
            "networkcore_mode",
            &[("mode", name)],
            u64::from(mode == value),
        );
    }

    for (name, help, value) in [
        (
            "networkcore_upload_bytes_total",
            "Bytes sent through the engine since it started.",
            traffic.upload_total,
        ),
        (
            "networkcore_download_bytes_total",
            "Bytes received through the engine since it started.",
            traffic.download_total,
        ),
    ] {
        out.family(name, "counter", help);
        out.sample(name, &[], value);
    }
    for (name, help, value) in [
        (
            "networkcore_upload_rate_bytes",
            "Current upload rate in bytes per second.",
            traffic.upload_rate,
        ),
        (
            "networkcore_download_rate_bytes",
            "Current download rate in bytes per second.",
            traffic.download_rate,
        ),
    ] {
        out.family(name, "gauge", help);
        out.sample(name, &[], value);
    }

    out.family(
        "networkcore_connections_active",
        "gauge",
        "Open connections and UDP flows.",
    );
    out.sample(
        "networkcore_connections_active",
        &[("network", "tcp")],
        counters.active_tcp as u64,
    );
    out.sample(
        "networkcore_connections_active",
        &[("network", "udp")],
        counters.active_udp as u64,
    );
    out.family(
        "networkcore_connections_opened_total",
        "counter",
        "Connections and UDP flows opened since the engine started.",
    );
    out.sample(
        "networkcore_connections_opened_total",
        &[("network", "tcp")],
        counters.opened_tcp,
    );
    out.sample(
        "networkcore_connections_opened_total",
        &[("network", "udp")],
        counters.opened_udp,
    );
    out.family(
        "networkcore_connections_closed_total",
        "counter",
        "Connections and UDP flows closed since the engine started, by result (ok, rejected, connect_failed).",
    );
    for network in [Network::Tcp, Network::Udp] {
        // `ok` is always written, so a scrape sees the series from the start.
        if !counters
            .closed
            .iter()
            .any(|(n, result, _)| *n == network && *result == "ok")
        {
            out.sample(
                "networkcore_connections_closed_total",
                &[("network", network.as_str()), ("result", "ok")],
                0,
            );
        }
    }
    for (network, result, count) in &counters.closed {
        out.sample(
            "networkcore_connections_closed_total",
            &[("network", network.as_str()), ("result", *result)],
            *count,
        );
    }

    let Some(routed) = dispatcher.routed_outbound() else {
        return out.0;
    };
    let groups = routed.groups();
    out.family(
        "networkcore_policy_group_selected",
        "gauge",
        "The member each policy group picks now; always 1.",
    );
    for (index, group) in groups.iter().enumerate() {
        let member_index = group
            .members
            .iter()
            .position(|member| member.name == group.now)
            .map_or(0, |i| i + 1);
        let (group_label, member_label) = match labels {
            Labels::Named => (group.id.clone(), group.now.clone()),
            Labels::Anonymous => (
                format!("group_{}", index + 1),
                format!("member_{member_index}"),
            ),
        };
        out.sample(
            "networkcore_policy_group_selected",
            &[
                ("group", group_label.as_str()),
                ("type", group.kind),
                ("member", member_label.as_str()),
            ],
            1,
        );
    }
    out.family(
        "networkcore_policy_member_latency_ms",
        "gauge",
        "Last health check latency of url-test and fallback group members.",
    );
    for (index, group) in groups.iter().enumerate() {
        for (member_index, member) in group.members.iter().enumerate() {
            let Some(latency) = member.latency_ms else {
                continue;
            };
            let (group_label, member_label) = match labels {
                Labels::Named => (group.id.clone(), member.name.clone()),
                Labels::Anonymous => (
                    format!("group_{}", index + 1),
                    format!("member_{}", member_index + 1),
                ),
            };
            out.sample(
                "networkcore_policy_member_latency_ms",
                &[
                    ("group", group_label.as_str()),
                    ("member", member_label.as_str()),
                ],
                u64::from(latency),
            );
        }
    }

    let sets = routed.rule_sets().status();
    out.family(
        "networkcore_rule_set_entries",
        "gauge",
        "Entries loaded in each rule set.",
    );
    for (index, set) in sets.iter().enumerate() {
        let name = match labels {
            Labels::Named => set.name.clone(),
            Labels::Anonymous => format!("rule_set_{}", index + 1),
        };
        out.sample(
            "networkcore_rule_set_entries",
            &[("rule_set", name.as_str()), ("source", set.source)],
            set.entries as u64,
        );
    }
    out.family(
        "networkcore_rule_set_failed",
        "gauge",
        "1 when the last download of a remote rule set failed.",
    );
    for (index, set) in sets.iter().enumerate() {
        if set.source != "remote" {
            continue;
        }
        let name = match labels {
            Labels::Named => set.name.clone(),
            Labels::Anonymous => format!("rule_set_{}", index + 1),
        };
        out.sample(
            "networkcore_rule_set_failed",
            &[("rule_set", name.as_str())],
            u64::from(set.last_error.is_some()),
        );
    }
    out.0
}

#[derive(Default)]
struct Text(String);

impl Text {
    fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: u64) {
        self.labels(name, labels);
        let _ = writeln!(self.0, " {value}");
    }

    fn sample_f64(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        self.labels(name, labels);
        let _ = writeln!(self.0, " {value:.3}");
    }

    fn labels(&mut self, name: &str, labels: &[(&str, &str)]) {
        self.0.push_str(name);
        if labels.is_empty() {
            return;
        }
        self.0.push('{');
        for (i, (key, value)) in labels.iter().enumerate() {
            if i > 0 {
                self.0.push(',');
            }
            self.0.push_str(key);
            self.0.push_str("=\"");
            escape_label(&mut self.0, value);
            self.0.push('"');
        }
        self.0.push('}');
    }
}

/// Label values escape backslash, double quote and line feed.
fn escape_label(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::escape_label;

    #[test]
    fn label_values_are_escaped() {
        let mut out = String::new();
        escape_label(&mut out, "a\"b\\c\nd");
        assert_eq!(out, "a\\\"b\\\\c\\nd");
    }
}
