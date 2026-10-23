//! Loon plugin import for the M3 P0 compatibility tier.
//!
//! A user-imported Loon plugin is split by owner: `#!` metadata and
//! `[Argument]` describe the plugin, `[MITM] hostname` feeds the MITM host
//! list, routing-level `[Rule]` lines become [`RoutingRule`]s for the shared
//! routing model, and HTTP rewrite lines stay in the plugin source that the
//! `mitm_anixops` core evaluates. Every non-comment line gets a support status,
//! so a plugin can be graded as fully, partially, or not supported before it
//! is enabled. Scripts, `[Map Local]`, and body rewrites belong to the P1 tier
//! and are reported as deferred.

use crate::{AnixOpsMitmPolicyEngine, MitmPolicyRuleDiagnosticStatus};
use config_core::routing::{parse_rule_line, PolicyTarget, RoutingModel, RoutingRule, RuleLine};
use control_domain::{
    DomainError, DomainResult, HookPoint, PluginManifest, PluginPackage, PluginPermission,
};
use std::fmt::Write as _;

pub const LOON_PLUGIN_MAX_BYTES: usize = 1024 * 1024;

pub const LOON_PLUGIN_TOO_LARGE_CODE: &str = "mitm.policy.loon_plugin.too_large";
pub const LOON_PLUGIN_EMPTY_CODE: &str = "mitm.policy.loon_plugin.empty";
pub const LOON_PLUGIN_ID_INVALID_CODE: &str = "mitm.policy.loon_plugin.id_invalid";

/// Plugin-level metadata from `#!key = value` lines and `[Argument]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoonPluginMetadata {
    pub name: Option<String>,
    pub desc: Option<String>,
    pub author: Option<String>,
    pub homepage: Option<String>,
    pub icon: Option<String>,
    pub category: Option<String>,
    /// Declared arguments as `(name, default)` pairs, in declaration order.
    pub arguments: Vec<(String, String)>,
}

/// How a plugin's `[MITM] hostname` list combines with the existing list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoonHostnameMode {
    /// `%APPEND%` / `%INSERT%`, or a plugin hostname line without a marker:
    /// plugins only ever add to the user's list.
    Append,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonMitmHostnames {
    pub mode: LoonHostnameMode,
    /// Host patterns to decrypt, lower-cased, in declaration order.
    pub include: Vec<String>,
    /// Host patterns listed with a `-` or `!` prefix, without the prefix.
    pub exclude: Vec<String>,
}

impl Default for LoonMitmHostnames {
    fn default() -> Self {
        Self {
            mode: LoonHostnameMode::Append,
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }
}

impl LoonMitmHostnames {
    /// Applies this plugin's hostname list to an existing list. Included
    /// patterns are appended once; excluded patterns are removed and recorded
    /// as `-pattern` so later plugins cannot re-enable them silently.
    pub fn apply(&self, existing: &[String]) -> Vec<String> {
        let mut merged = existing
            .iter()
            .filter(|pattern| {
                let pattern = pattern.trim().to_ascii_lowercase();
                !self.exclude.contains(&pattern)
            })
            .cloned()
            .collect::<Vec<_>>();
        for pattern in &self.include {
            if self.exclude.contains(pattern) {
                continue;
            }
            if !merged
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(pattern))
            {
                merged.push(pattern.clone());
            }
        }
        for pattern in &self.exclude {
            let marker = format!("-{pattern}");
            if !merged.contains(&marker) {
                merged.push(marker);
            }
        }
        merged
    }
}

/// Support status of one plugin line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoonLineStatus {
    /// The line takes full effect.
    Supported,
    /// The line takes effect with narrower semantics than in Loon.
    Partial,
    /// The line belongs to a later tier (scripts, map local, body rewrites).
    Deferred,
    /// The line has no effect.
    Unsupported,
    /// Informational line that never affects traffic.
    Ignored,
}

impl LoonLineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Partial => "partial",
            Self::Deferred => "deferred",
            Self::Unsupported => "unsupported",
            Self::Ignored => "ignored",
        }
    }
}

/// Component that enforces a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoonLineHandler {
    Metadata,
    MitmHostnames,
    Routing,
    PolicyEngine,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonLineReport {
    /// 1-based line number in the plugin text.
    pub line: usize,
    pub section: String,
    pub status: LoonLineStatus,
    pub handler: LoonLineHandler,
    /// Stable reason, for example `rewrite.reject` or `rule.type_unsupported`.
    pub reason: String,
}

/// Overall grade of a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoonSupportLevel {
    /// Every effective line is supported.
    Full,
    /// Some effective lines are partial, deferred, or unsupported.
    Partial,
    /// No effective line is supported, or the policy core refused the plugin.
    Unsupported,
}

impl LoonSupportLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonPluginReport {
    pub level: LoonSupportLevel,
    pub lines: Vec<LoonLineReport>,
    /// Set when the `mitm_anixops` core refused the whole plugin.
    pub policy_load_error: Option<String>,
}

impl LoonPluginReport {
    pub fn count(&self, status: LoonLineStatus) -> usize {
        self.lines
            .iter()
            .filter(|line| line.status == status)
            .count()
    }

    /// Renders a stable, credential-free text summary for CI logs.
    pub fn render_text(&self, plugin_label: &str) -> String {
        let mut text = String::new();
        let _ = writeln!(
            text,
            "{plugin_label}: {} (supported {}, partial {}, deferred {}, unsupported {})",
            self.level.as_str(),
            self.count(LoonLineStatus::Supported),
            self.count(LoonLineStatus::Partial),
            self.count(LoonLineStatus::Deferred),
            self.count(LoonLineStatus::Unsupported),
        );
        if let Some(error) = &self.policy_load_error {
            let _ = writeln!(text, "  policy core refused the plugin: {error}");
        }
        for line in &self.lines {
            if matches!(
                line.status,
                LoonLineStatus::Supported | LoonLineStatus::Ignored
            ) {
                continue;
            }
            let _ = writeln!(
                text,
                "  line {} [{}] {}: {}",
                line.line,
                line.section,
                line.status.as_str(),
                line.reason
            );
        }
        text
    }
}

/// Routing rule contributed by a plugin `[Rule]` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonPluginRule {
    pub line: usize,
    pub rule: RoutingRule,
}

/// Result of importing one Loon plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonPluginImport {
    pub metadata: LoonPluginMetadata,
    pub mitm_hostnames: LoonMitmHostnames,
    pub rules: Vec<LoonPluginRule>,
    pub report: LoonPluginReport,
    has_request_actions: bool,
    has_response_actions: bool,
    source: String,
}

impl LoonPluginImport {
    /// Plugin text evaluated by the `mitm_anixops` core.
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn routing_rules(&self) -> Vec<RoutingRule> {
        self.rules.iter().map(|rule| rule.rule.clone()).collect()
    }

    /// Builds the package loaded by [`crate::AnixOpsMitmPluginService`].
    /// Hooks and permissions cover only the phases the plugin rewrites.
    pub fn plugin_package(&self, id: &str, version: &str) -> DomainResult<PluginPackage> {
        let id = id.trim();
        if id.is_empty()
            || !id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
        {
            return Err(DomainError::new(
                LOON_PLUGIN_ID_INVALID_CODE,
                "Loon plugin id must be non-empty ASCII letters, digits, '.', '-', or '_'",
            ));
        }

        let mut permissions = Vec::new();
        let mut hooks = Vec::new();
        if self.has_request_actions || !self.has_response_actions {
            permissions.extend([
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ]);
            hooks.push(HookPoint::Request);
        }
        if self.has_response_actions {
            permissions.extend([
                PluginPermission::ReadResponse,
                PluginPermission::ModifyResponse,
            ]);
            hooks.push(HookPoint::Response);
        }

        Ok(PluginPackage {
            manifest: PluginManifest {
                id: id.to_string(),
                version: version.to_string(),
                permissions,
                hooks,
            },
            source: self.source.clone(),
        })
    }
}

/// Returns a copy of `model` whose rules start with the plugins' routing
/// rules, in plugin order. Plugin rules only add REJECT and DIRECT decisions,
/// so they never reference user nodes or policy groups.
pub fn routing_model_with_plugin_rules(
    model: &RoutingModel,
    plugins: &[&LoonPluginImport],
) -> RoutingModel {
    let mut rules = plugins
        .iter()
        .flat_map(|plugin| plugin.routing_rules())
        .collect::<Vec<_>>();
    rules.extend(model.rules.iter().cloned());
    RoutingModel {
        rules,
        final_target: model.final_target.clone(),
        groups: model.groups.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Preamble,
    Plugin,
    Argument,
    Rule,
    Rewrite,
    HeaderRewrite,
    BodyRewrite,
    Script,
    MapLocal,
    Mitm,
    Other,
}

impl Section {
    fn parse(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "plugin" => Self::Plugin,
            "argument" => Self::Argument,
            "rule" => Self::Rule,
            "rewrite" | "url rewrite" | "remote rewrite" => Self::Rewrite,
            "header rewrite" | "remote header rewrite" => Self::HeaderRewrite,
            "body rewrite" | "remote body rewrite" => Self::BodyRewrite,
            "script" => Self::Script,
            "map local" => Self::MapLocal,
            "mitm" => Self::Mitm,
            _ => Self::Other,
        }
    }
}

const METADATA_KEYS: [&str; 6] = ["name", "desc", "author", "homepage", "icon", "category"];

/// Parses a Loon plugin and grades every line. The `mitm_anixops` core is
/// consulted for the HTTP rewrite lines it owns; a plugin it refuses is graded
/// unsupported as a whole.
pub fn import_loon_plugin(text: &str) -> DomainResult<LoonPluginImport> {
    if text.len() > LOON_PLUGIN_MAX_BYTES {
        return Err(DomainError::new(
            LOON_PLUGIN_TOO_LARGE_CODE,
            format!("Loon plugin exceeds {LOON_PLUGIN_MAX_BYTES} bytes"),
        ));
    }
    if text.trim().is_empty() {
        return Err(DomainError::new(
            LOON_PLUGIN_EMPTY_CODE,
            "Loon plugin is empty",
        ));
    }

    let mut parser = Parser::default();
    let mut section = Section::Preamble;
    let mut section_name = String::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(meta) = line.strip_prefix("#!") {
            parser.metadata_line(line_number, &section_name, meta);
            continue;
        }
        if line.starts_with('#') || line.starts_with(';') || line.starts_with("//") {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section_name = line[1..line.len() - 1].trim().to_string();
            section = Section::parse(&section_name);
            if section == Section::Other {
                parser.push(
                    line_number,
                    &section_name,
                    LoonLineStatus::Unsupported,
                    LoonLineHandler::None,
                    "section.unsupported",
                );
            }
            continue;
        }

        match section {
            Section::Preamble | Section::Plugin => parser.push(
                line_number,
                &section_name,
                LoonLineStatus::Ignored,
                LoonLineHandler::Metadata,
                "metadata.plugin_section",
            ),
            Section::Argument => parser.argument_line(line_number, &section_name, line),
            Section::Rule => parser.rule_line(line_number, &section_name, line),
            Section::Rewrite | Section::HeaderRewrite => {
                parser.rewrite_line(line_number, &section_name, line)
            }
            Section::BodyRewrite => {
                parser.has_response_actions = true;
                parser.push(
                    line_number,
                    &section_name,
                    LoonLineStatus::Deferred,
                    LoonLineHandler::PolicyEngine,
                    "body_rewrite.p1",
                )
            }
            Section::Script => {
                parser.push(
                    line_number,
                    &section_name,
                    LoonLineStatus::Deferred,
                    LoonLineHandler::None,
                    "script.p1",
                );
            }
            Section::MapLocal => parser.push(
                line_number,
                &section_name,
                LoonLineStatus::Deferred,
                LoonLineHandler::None,
                "map_local.p1",
            ),
            Section::Mitm => parser.mitm_line(line_number, &section_name, line),
            Section::Other => parser.push(
                line_number,
                &section_name,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "section.unsupported",
            ),
        }
    }

    let policy_load_error = parser.cross_check_with_policy_core(text);
    let level = grade(&parser.lines, policy_load_error.is_some());
    Ok(LoonPluginImport {
        metadata: parser.metadata,
        mitm_hostnames: parser.mitm_hostnames,
        rules: parser.rules,
        report: LoonPluginReport {
            level,
            lines: parser.lines,
            policy_load_error,
        },
        has_request_actions: parser.has_request_actions,
        has_response_actions: parser.has_response_actions,
        source: text.to_string(),
    })
}

#[derive(Default)]
struct Parser {
    metadata: LoonPluginMetadata,
    mitm_hostnames: LoonMitmHostnames,
    rules: Vec<LoonPluginRule>,
    lines: Vec<LoonLineReport>,
    has_request_actions: bool,
    has_response_actions: bool,
}

impl Parser {
    fn push(
        &mut self,
        line: usize,
        section: &str,
        status: LoonLineStatus,
        handler: LoonLineHandler,
        reason: &str,
    ) {
        self.lines.push(LoonLineReport {
            line,
            section: section.to_string(),
            status,
            handler,
            reason: reason.to_string(),
        });
    }

    fn metadata_line(&mut self, line: usize, section: &str, meta: &str) {
        let (key, value) = match meta.split_once('=') {
            Some((key, value)) => (key.trim().to_ascii_lowercase(), value.trim().to_string()),
            None => (meta.trim().to_ascii_lowercase(), String::new()),
        };
        let value = Some(value).filter(|value| !value.is_empty());
        match key.as_str() {
            "name" => self.metadata.name = value.or(self.metadata.name.take()),
            "desc" => self.metadata.desc = value.or(self.metadata.desc.take()),
            "author" => self.metadata.author = value.or(self.metadata.author.take()),
            "homepage" => self.metadata.homepage = value.or(self.metadata.homepage.take()),
            "icon" => self.metadata.icon = value.or(self.metadata.icon.take()),
            "category" => self.metadata.category = value.or(self.metadata.category.take()),
            "arguments" => {
                for entry in value.unwrap_or_default().split(',') {
                    if let Some((name, default)) = entry.split_once(':') {
                        self.add_argument(name, default);
                    }
                }
            }
            _ => {}
        }
        let reason = if METADATA_KEYS.contains(&key.as_str()) || key == "arguments" {
            "metadata.recognized"
        } else {
            "metadata.unrecognized"
        };
        self.push(
            line,
            section,
            LoonLineStatus::Ignored,
            LoonLineHandler::Metadata,
            reason,
        );
    }

    fn add_argument(&mut self, name: &str, default: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        let default = default.trim().trim_matches('"').to_string();
        if let Some(existing) = self
            .metadata
            .arguments
            .iter_mut()
            .find(|(existing, _)| existing == name)
        {
            existing.1 = default;
        } else {
            self.metadata.arguments.push((name.to_string(), default));
        }
    }

    fn argument_line(&mut self, line: usize, section: &str, text: &str) {
        // `Name = kind,default[,tag=...]`
        let status = match text.split_once('=') {
            Some((name, spec)) => {
                let default = spec.split(',').nth(1).unwrap_or("");
                self.add_argument(name, default);
                LoonLineStatus::Ignored
            }
            None => LoonLineStatus::Unsupported,
        };
        let reason = if status == LoonLineStatus::Ignored {
            "argument.declared"
        } else {
            "argument.invalid"
        };
        self.push(line, section, status, LoonLineHandler::Metadata, reason);
    }

    fn mitm_line(&mut self, line: usize, section: &str, text: &str) {
        let Some((key, value)) = text.split_once('=') else {
            self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "mitm.invalid",
            );
            return;
        };
        let key = key.trim().to_ascii_lowercase();
        match key.as_str() {
            "hostname" => {
                for item in value.split(',') {
                    let mut item = item.trim();
                    for marker in ["%APPEND%", "%INSERT%"] {
                        if item
                            .get(..marker.len())
                            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(marker))
                        {
                            item = item[marker.len()..].trim();
                        }
                    }
                    if item.is_empty() {
                        continue;
                    }
                    let pattern = item.to_ascii_lowercase();
                    if let Some(excluded) = pattern
                        .strip_prefix('-')
                        .or_else(|| pattern.strip_prefix('!'))
                    {
                        let excluded = excluded.trim().to_string();
                        if !excluded.is_empty() && !self.mitm_hostnames.exclude.contains(&excluded)
                        {
                            self.mitm_hostnames.exclude.push(excluded);
                        }
                    } else if !self.mitm_hostnames.include.contains(&pattern) {
                        self.mitm_hostnames.include.push(pattern);
                    }
                }
                self.push(
                    line,
                    section,
                    LoonLineStatus::Supported,
                    LoonLineHandler::MitmHostnames,
                    "mitm.hostname",
                );
            }
            // Certificate verification is never skipped for plugin hosts.
            "skip-server-cert-verify" => self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "mitm.skip_server_cert_verify_refused",
            ),
            _ => self.push(
                line,
                section,
                LoonLineStatus::Ignored,
                LoonLineHandler::None,
                "mitm.option_ignored",
            ),
        }
    }

    fn rule_line(&mut self, line: usize, section: &str, text: &str) {
        let parts = text.split(',').map(str::trim).collect::<Vec<_>>();
        let kind = parts[0].to_ascii_uppercase();
        let target = parts.get(2).copied().unwrap_or("");
        let reject = is_reject_policy(target);

        match kind.as_str() {
            // Request URLs are only visible after decryption, so the policy
            // core enforces URL-REGEX rejects on MITM hosts.
            "URL-REGEX" => {
                let (status, handler, reason) = if reject {
                    self.has_request_actions = true;
                    (
                        LoonLineStatus::Supported,
                        LoonLineHandler::PolicyEngine,
                        "rule.url_regex_reject",
                    )
                } else {
                    (
                        LoonLineStatus::Unsupported,
                        LoonLineHandler::None,
                        "rule.policy_unsupported",
                    )
                };
                self.push(line, section, status, handler, reason);
            }
            "FINAL" => self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "rule.final_in_plugin",
            ),
            _ => self.routing_rule_line(line, section, text, target, reject),
        }
    }

    fn routing_rule_line(
        &mut self,
        line: usize,
        section: &str,
        text: &str,
        target: &str,
        reject: bool,
    ) {
        let policy = if reject {
            PolicyTarget::Reject
        } else if target.eq_ignore_ascii_case("DIRECT") {
            PolicyTarget::Direct
        } else {
            // Plugins cannot know the user's node and group names.
            self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "rule.policy_unsupported",
            );
            return;
        };

        match parse_rule_line(text) {
            Ok(RuleLine::Rule {
                matcher,
                no_resolve,
                ..
            }) => {
                self.rules.push(LoonPluginRule {
                    line,
                    rule: RoutingRule {
                        matcher,
                        target: policy,
                        no_resolve,
                    },
                });
                self.push(
                    line,
                    section,
                    LoonLineStatus::Supported,
                    LoonLineHandler::Routing,
                    "rule.routing",
                );
            }
            Ok(RuleLine::Final { .. }) => self.push(
                line,
                section,
                LoonLineStatus::Unsupported,
                LoonLineHandler::None,
                "rule.final_in_plugin",
            ),
            Err(error) => {
                let reason =
                    if error.code == config_core::routing::ROUTING_RULE_TYPE_UNSUPPORTED_CODE {
                        "rule.type_unsupported"
                    } else {
                        "rule.invalid"
                    };
                self.push(
                    line,
                    section,
                    LoonLineStatus::Unsupported,
                    LoonLineHandler::None,
                    reason,
                );
            }
        }
    }

    fn rewrite_line(&mut self, line: usize, section: &str, text: &str) {
        let mut tokens = text.split_whitespace();
        let first = tokens.next().unwrap_or("");
        // Quantumult X style lines start with `url`.
        let action = if first.eq_ignore_ascii_case("url") {
            tokens.nth(1)
        } else {
            tokens.next()
        }
        .unwrap_or("")
        .to_ascii_lowercase();

        let (status, reason, response) = classify_rewrite_action(&action);
        if status != LoonLineStatus::Unsupported {
            if response {
                self.has_response_actions = true;
            } else {
                self.has_request_actions = true;
            }
        }
        let handler = if status == LoonLineStatus::Unsupported {
            LoonLineHandler::None
        } else {
            LoonLineHandler::PolicyEngine
        };
        self.push(line, section, status, handler, reason);
    }

    /// Loads the plugin into the policy core and downgrades lines it owns but
    /// did not accept. Returns the load error when the core refuses the text.
    fn cross_check_with_policy_core(&mut self, text: &str) -> Option<String> {
        let mut engine = match AnixOpsMitmPolicyEngine::new() {
            Ok(engine) => engine,
            Err(error) => return Some(error.message),
        };
        let report = match engine.load_config(text) {
            Ok(report) => report,
            Err(error) => return Some(error.message),
        };
        for diagnostic in &report.rule_diagnostics {
            if diagnostic.status == MitmPolicyRuleDiagnosticStatus::Accepted {
                continue;
            }
            for line in self
                .lines
                .iter_mut()
                .filter(|line| line.line == diagnostic.line)
            {
                let owned_by_core = line.handler == LoonLineHandler::PolicyEngine;
                if owned_by_core && line.status != LoonLineStatus::Deferred {
                    line.status = LoonLineStatus::Unsupported;
                    line.handler = LoonLineHandler::None;
                    line.reason = match diagnostic.status {
                        MitmPolicyRuleDiagnosticStatus::Rejected => "policy_core.rejected",
                        _ => "policy_core.ignored",
                    }
                    .to_string();
                }
            }
        }
        None
    }
}

fn is_reject_policy(target: &str) -> bool {
    let target = target.to_ascii_uppercase();
    target == "REJECT" || target.starts_with("REJECT-")
}

/// Returns the status, reason, and whether the action applies to responses.
fn classify_rewrite_action(action: &str) -> (LoonLineStatus, &'static str, bool) {
    match action {
        "reject" | "reject-200" | "reject-img" | "reject-tinygif" | "reject-dict"
        | "reject-array" | "reject-video" | "reject-drop" | "reject-no-drop" => {
            (LoonLineStatus::Supported, "rewrite.reject", false)
        }
        "301" | "302" | "303" | "307" | "308" => {
            (LoonLineStatus::Supported, "rewrite.redirect", false)
        }
        "header-add" | "header-del" | "header-replace" | "header-replace-regex" => {
            (LoonLineStatus::Supported, "rewrite.request_header", false)
        }
        "response-header-add"
        | "response-header-del"
        | "response-header-replace"
        | "response-header-replace-regex" => {
            (LoonLineStatus::Supported, "rewrite.response_header", true)
        }
        _ if action.strip_prefix("reject-").is_some_and(|code| {
            code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit())
        }) =>
        {
            (LoonLineStatus::Supported, "rewrite.reject", false)
        }
        _ if action.starts_with("request-body-") || action == "mock-request-body" => {
            (LoonLineStatus::Deferred, "rewrite.body_p1", false)
        }
        _ if action.starts_with("response-body-") || action == "mock-response-body" => {
            (LoonLineStatus::Deferred, "rewrite.body_p1", true)
        }
        _ => (
            LoonLineStatus::Unsupported,
            "rewrite.action_unsupported",
            false,
        ),
    }
}

fn grade(lines: &[LoonLineReport], refused: bool) -> LoonSupportLevel {
    if refused {
        return LoonSupportLevel::Unsupported;
    }
    let effective = lines
        .iter()
        .filter(|line| line.status != LoonLineStatus::Ignored)
        .collect::<Vec<_>>();
    let supported = effective
        .iter()
        .filter(|line| line.status == LoonLineStatus::Supported)
        .count();
    if supported == 0 {
        LoonSupportLevel::Unsupported
    } else if supported == effective.len() {
        LoonSupportLevel::Full
    } else {
        LoonSupportLevel::Partial
    }
}
