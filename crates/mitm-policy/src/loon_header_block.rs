//! Quantumult X header-block rewrites:
//! `<url> url request-header <regex> request-header <replacement>` (and the
//! `response-header` form) run a regex over the whole header block, start
//! line included, the way Quantumult X sees it:
//!
//! ```text
//! GET /path?query HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n
//! ```
//!
//! The core has no such rule. The importer keeps the lines in an
//! `[AnixOps Header Block]` section, which the core skips; at run time the
//! core matches the URL pattern and, as a body rewrite over the block text,
//! does the replacement, so the regex and `$1` replacements behave as in the
//! other regex rules. The block is then read back: changed headers become
//! header mutations, and a request whose path or `Host` changed is
//! redirected to the new URL, the closest the data plane has to sending the
//! request elsewhere.

use crate::loon_syntax::{quote, tokens};
use crate::{AnixOpsMitmPolicyEngine, MitmPolicyPhase};
use control_domain::{
    DomainResult, HttpHeaderMutation, HttpHeaderMutationOperation, HttpMitmPhase, MetadataEntry,
};

/// Section the importer writes the rules to; the core ignores it.
pub const HEADER_BLOCK_SECTION: &str = "AnixOps Header Block";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonHeaderBlockRule {
    pub response: bool,
    pub url_pattern: String,
    pub regex: String,
    pub replacement: String,
}

impl LoonHeaderBlockRule {
    /// The rule as a line of [`HEADER_BLOCK_SECTION`].
    pub fn line(&self) -> String {
        format!(
            "{} {} {} {}",
            if self.response {
                "response-header"
            } else {
                "request-header"
            },
            quote(&self.url_pattern),
            quote(&self.regex),
            quote(&self.replacement)
        )
    }

    fn parse(line: &str) -> Option<Self> {
        let parts = tokens(line);
        let [kind, url_pattern, regex, replacement] = parts.as_slice() else {
            return None;
        };
        let response = match kind.as_str() {
            "request-header" => false,
            "response-header" => true,
            _ => return None,
        };
        Some(Self {
            response,
            url_pattern: url_pattern.clone(),
            regex: regex.clone(),
            replacement: replacement.clone(),
        })
    }
}

/// What a header-block rewrite does to one message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderBlockOutcome {
    /// New URL of a request whose path or `Host` changed.
    pub redirect: Option<String>,
    pub header_mutations: Vec<HttpHeaderMutation>,
}

/// The rules of [`HEADER_BLOCK_SECTION`] in `source`.
pub fn header_block_rules(source: &str) -> Vec<LoonHeaderBlockRule> {
    let mut rules = Vec::new();
    let mut inside = false;
    for line in source.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            inside = line[1..line.len() - 1]
                .trim()
                .eq_ignore_ascii_case(HEADER_BLOCK_SECTION);
            continue;
        }
        if inside && !line.is_empty() && !line.starts_with('#') {
            rules.extend(LoonHeaderBlockRule::parse(line));
        }
    }
    rules
}

/// Applies the first matching rule of `source` to a message. `None` when no
/// rule matches or the block comes back unchanged.
pub fn apply_header_block(
    source: &str,
    url: &str,
    phase: HttpMitmPhase,
    method: Option<&str>,
    status_code: Option<u16>,
    headers: &[MetadataEntry],
) -> DomainResult<Option<HeaderBlockOutcome>> {
    let response = phase == HttpMitmPhase::Response;
    let rules = header_block_rules(source)
        .into_iter()
        .filter(|rule| rule.response == response)
        .collect::<Vec<_>>();
    let Some(rule) = first_matching(&rules, url)? else {
        return Ok(None);
    };
    let (scheme, authority, path) = split_url(url);
    let start_line = if response {
        let status = status_code.unwrap_or(200);
        format!("HTTP/1.1 {status} {}", reason(status))
    } else {
        format!("{} {path} HTTP/1.1", method.unwrap_or("GET"))
    };
    let mut block = start_line.clone();
    block.push_str("\r\n");
    let has_host = headers
        .iter()
        .any(|header| header.key.eq_ignore_ascii_case("host"));
    if !response && !has_host {
        block.push_str(&format!("Host: {authority}\r\n"));
    }
    for header in headers {
        block.push_str(&format!("{}: {}\r\n", header.key, header.value));
    }
    block.push_str("\r\n");

    let action = if response {
        "response-body-replace-regex"
    } else {
        "request-body-replace-regex"
    };
    let config = format!(
        "[Rewrite]\n{} {action} {} {}\n",
        quote(&rule.url_pattern),
        quote(&rule.regex),
        quote(&rule.replacement)
    );
    let mut engine = AnixOpsMitmPolicyEngine::new()?;
    if engine.load_config(&config).is_err() {
        return Ok(None);
    }
    let policy_phase = if response {
        MitmPolicyPhase::Response
    } else {
        MitmPolicyPhase::Request
    };
    let (rewritten, chain) = engine.apply_body_chain(url, policy_phase, &block)?;
    if !chain.rewritten || chain.truncated || rewritten == block {
        return Ok(None);
    }

    let mut lines = rewritten.split("\r\n");
    let new_start = lines.next().unwrap_or_default().to_string();
    let new_headers = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .filter(|(key, _)| !key.is_empty())
        .collect::<Vec<_>>();
    let mut outcome = HeaderBlockOutcome::default();

    if !response {
        let new_path = new_start
            .split(' ')
            .nth(1)
            .filter(|path| path.starts_with('/'))
            .unwrap_or(path);
        let new_host = new_headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.as_str())
            .unwrap_or(authority);
        if new_path != path || !new_host.eq_ignore_ascii_case(authority) {
            outcome.redirect = Some(format!("{scheme}://{new_host}{new_path}"));
            return Ok(Some(outcome));
        }
    }

    // Each header whose values changed is deleted and written again.
    let values = |list: &[(String, String)], name: &str| {
        list.iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>()
    };
    let old_headers = headers
        .iter()
        .map(|header| (header.key.clone(), header.value.trim().to_string()))
        .collect::<Vec<_>>();
    let mut names = Vec::<String>::new();
    for (key, _) in old_headers.iter().chain(&new_headers) {
        if !names.iter().any(|name| name.eq_ignore_ascii_case(key)) {
            names.push(key.clone());
        }
    }
    for name in names {
        if name.eq_ignore_ascii_case("host") && !has_host {
            continue;
        }
        let (old, new) = (values(&old_headers, &name), values(&new_headers, &name));
        if old == new {
            continue;
        }
        if !old.is_empty() {
            outcome.header_mutations.push(HttpHeaderMutation {
                operation: HttpHeaderMutationOperation::Delete,
                name: name.clone(),
                value: None,
            });
        }
        let new_name = new_headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(&name))
            .map_or(name.clone(), |(key, _)| key.clone());
        for value in new {
            outcome.header_mutations.push(HttpHeaderMutation {
                operation: HttpHeaderMutationOperation::Add,
                name: new_name.clone(),
                value: Some(value),
            });
        }
    }
    Ok((!outcome.header_mutations.is_empty()).then_some(outcome))
}

/// The first rule whose URL pattern the core matches against `url`.
fn first_matching(
    rules: &[LoonHeaderBlockRule],
    url: &str,
) -> DomainResult<Option<LoonHeaderBlockRule>> {
    if rules.is_empty() {
        return Ok(None);
    }
    // One load for every pattern; the matched pattern names the rule.
    let mut config = String::from("[Rewrite]\n");
    for rule in rules {
        config.push_str(&quote(&rule.url_pattern));
        config.push_str(" reject\n");
    }
    let mut engine = AnixOpsMitmPolicyEngine::new()?;
    if engine.load_config(&config).is_ok() {
        let result = engine.evaluate_url_rewrite(url, MitmPolicyPhase::Request)?;
        return Ok(rules
            .iter()
            .find(|rule| result.rule_index >= 0 && rule.url_pattern == result.matched_pattern)
            .cloned());
    }
    // A pattern the core refuses fails the whole load: try them one by one.
    for rule in rules {
        let config = format!("[Rewrite]\n{} reject\n", quote(&rule.url_pattern));
        let mut engine = AnixOpsMitmPolicyEngine::new()?;
        if engine.load_config(&config).is_err() {
            continue;
        }
        let result = engine.evaluate_url_rewrite(url, MitmPolicyPhase::Request)?;
        if result.rule_index >= 0 {
            return Ok(Some(rule.clone()));
        }
    }
    Ok(None)
}

/// Scheme, authority and path (with query) of `url`.
fn split_url(url: &str) -> (&str, &str, &str) {
    let (scheme, rest) = url.split_once("://").unwrap_or(("https", url));
    match rest.find('/') {
        Some(slash) => (scheme, &rest[..slash], &rest[slash..]),
        None => (scheme, rest, "/"),
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Status",
    }
}
