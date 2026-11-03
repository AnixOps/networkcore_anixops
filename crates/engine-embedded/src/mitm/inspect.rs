//! What the app shows and downloads for one imported plugin, without
//! starting a tunnel: `networkcore_ios_mitm_inspect_plugin`.

use mitm_policy::loon_plugin::{import_loon_plugin, LoonLineStatus, LoonPluginImport};
use serde_json::{json, Value};

/// Largest plugin text accepted across the boundary.
pub const MAX_PLUGIN_LEN: usize = mitm_policy::loon_plugin::LOON_PLUGIN_MAX_BYTES;

/// Imports `text` and describes it as JSON:
///
/// ```json
/// {"name": "…", "level": "full|partial|unsupported",
///  "hostnames": ["…"], "excluded_hostnames": ["…"],
///  "lines": {"supported": 3, "partial": 0, "unsupported": 1, "deferred": 0},
///  "resources": [{"url": "https://…", "kind": "script|map_local_data", "line": 7}],
///  "report": "…"}
/// ```
///
/// `resources` are the remote files the app downloads: scripts after the
/// user consents, `map_local_data` as plain data for `resource_assets`.
/// `None` when the text is not UTF-8, empty or too large.
pub fn inspect_plugin_json(text: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(text).ok()?;
    let plugin = import_loon_plugin(text).ok()?;
    serde_json::to_vec(&describe(&plugin)).ok()
}

fn describe(plugin: &LoonPluginImport) -> Value {
    let report = &plugin.report;
    json!({
        "name": plugin.metadata.name,
        "level": report.level.as_str(),
        "hostnames": plugin.mitm_hostnames.include,
        "excluded_hostnames": plugin.mitm_hostnames.exclude,
        "lines": {
            "supported": report.count(LoonLineStatus::Supported),
            "partial": report.count(LoonLineStatus::Partial),
            "unsupported": report.count(LoonLineStatus::Unsupported),
            "deferred": report.count(LoonLineStatus::Deferred),
        },
        "resources": plugin
            .remote_resources
            .iter()
            .map(|resource| json!({
                "url": resource.url,
                "kind": resource.kind.as_str(),
                "line": resource.line,
            }))
            .collect::<Vec<_>>(),
        "report": report.render_text(plugin.metadata.name.as_deref().unwrap_or("plugin")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_quantumult_scripts_and_remote_map_local_data() {
        let text = concat!(
            "#!name = Inspect\n",
            "[rewrite_local]\n",
            "^https?://a\\.example\\.com/s url script-response-body https://cdn.example.com/s.js\n",
            "^https?://a\\.example\\.com/e url echo-response text/json echo-response https://cdn.example.com/e.json\n",
            "[mitm]\n",
            "hostname = a.example.com, -b.example.com\n",
        );
        let value: Value =
            serde_json::from_slice(&inspect_plugin_json(text.as_bytes()).unwrap()).unwrap();
        assert_eq!(value["name"], "Inspect");
        assert_eq!(value["level"], "partial");
        assert_eq!(value["hostnames"], json!(["a.example.com"]));
        assert_eq!(value["excluded_hostnames"], json!(["b.example.com"]));
        assert_eq!(value["lines"]["unsupported"], 1);
        assert_eq!(
            value["resources"],
            json!([
                {"url": "https://cdn.example.com/s.js", "kind": "script", "line": 3},
                {"url": "https://cdn.example.com/e.json", "kind": "map_local_data", "line": 4},
            ])
        );
        assert!(inspect_plugin_json(b"").is_none());
        assert!(inspect_plugin_json(&[0xff, 0xfe]).is_none());
    }
}
