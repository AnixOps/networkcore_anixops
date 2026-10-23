//! Loon `[Map Local]`: answer a matching request with a local response
//! without contacting the origin.
//!
//! A line is `<url-regex> [data-type=text|json|html|base64|tiny-gif]
//! [data="..."] [status-code=200] [header="Name:Value|Name:Value"]`. The URL
//! regex is matched by the `mitm_anixops` core, so it has the same dialect as
//! `[Rewrite]` patterns. Remote `data` URLs are not fetched.

use crate::loon_syntax::{attributes, quote, tokens};
use crate::{AnixOpsMitmPolicyEngine, MitmPolicyPhase};
use control_domain::{DomainResult, MetadataEntry};

const TINY_GIF: [u8; 43] = [
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

/// One parsed `[Map Local]` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoonMapLocalRule {
    pub pattern: String,
    pub status_code: u16,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
}

/// Parses one `[Map Local]` line. The error is a stable report reason.
pub fn parse_map_local_line(text: &str) -> Result<LoonMapLocalRule, &'static str> {
    let Some(pattern) = tokens(text).into_iter().next().filter(|p| !p.is_empty()) else {
        return Err("map_local.pattern_missing");
    };
    let rest = text
        .trim_start()
        .get(pattern_source_len(text.trim_start())..)
        .unwrap_or("");

    let mut data_type = String::from("text");
    let mut data = None;
    let mut status_code = 200;
    let mut extra_headers = Vec::new();
    for (key, value) in attributes(rest) {
        match key.as_str() {
            "data-type" => data_type = value.to_ascii_lowercase(),
            "data" => data = Some(value),
            "status-code" => {
                status_code = value
                    .parse::<u16>()
                    .ok()
                    .filter(|code| (100..=599).contains(code))
                    .ok_or("map_local.status_invalid")?;
            }
            "header" => {
                for entry in value.split('|').filter(|entry| !entry.trim().is_empty()) {
                    let (name, value) = entry.split_once(':').ok_or("map_local.header_invalid")?;
                    let name = name.trim();
                    if name.is_empty()
                        || !name
                            .bytes()
                            .all(|byte| byte.is_ascii_graphic() && byte != b':')
                        || value.contains(['\r', '\n'])
                    {
                        return Err("map_local.header_invalid");
                    }
                    extra_headers.push(MetadataEntry {
                        key: name.to_string(),
                        value: value.trim().to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    let data = data.unwrap_or_default();
    if !matches!(data_type.as_str(), "tiny-gif" | "gif")
        && (data.starts_with("http://") || data.starts_with("https://"))
    {
        return Err("map_local.remote_data_unsupported");
    }
    let (content_type, body) = match data_type.as_str() {
        "text" => ("text/plain; charset=utf-8", data.into_bytes()),
        "json" => ("application/json; charset=utf-8", data.into_bytes()),
        "html" => ("text/html; charset=utf-8", data.into_bytes()),
        "base64" => (
            "application/octet-stream",
            decode_base64(&data).ok_or("map_local.base64_invalid")?,
        ),
        "tiny-gif" | "gif" => ("image/gif", TINY_GIF.to_vec()),
        _ => return Err("map_local.data_type_unsupported"),
    };

    let mut headers = Vec::new();
    if !extra_headers
        .iter()
        .any(|header| header.key.eq_ignore_ascii_case("Content-Type"))
    {
        headers.push(MetadataEntry {
            key: "Content-Type".to_string(),
            value: content_type.to_string(),
        });
    }
    headers.extend(extra_headers);
    Ok(LoonMapLocalRule {
        pattern,
        status_code,
        headers,
        body,
    })
}

/// Byte length of the first token as written, including its quotes.
pub(crate) fn pattern_source_len(text: &str) -> usize {
    let mut chars = text.char_indices();
    let Some((_, first)) = chars.next() else {
        return 0;
    };
    if matches!(first, '"' | '\'') {
        let mut escaped = false;
        for (index, ch) in chars {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == first {
                return index + ch.len_utf8();
            }
        }
        return text.len();
    }
    text.find(char::is_whitespace).unwrap_or(text.len())
}

/// Valid rules of every `[Map Local]` section in a plugin, in order.
pub fn map_local_rules(source: &str) -> Vec<LoonMapLocalRule> {
    let mut rules = Vec::new();
    let mut in_map_local = false;
    for line in source.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            in_map_local = line[1..line.len() - 1]
                .trim()
                .eq_ignore_ascii_case("map local");
            continue;
        }
        if !in_map_local
            || line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        if let Ok(rule) = parse_map_local_line(line) {
            rules.push(rule);
        }
    }
    rules
}

/// Returns the first `[Map Local]` rule whose pattern matches `url`.
pub fn match_map_local(source: &str, url: &str) -> DomainResult<Option<LoonMapLocalRule>> {
    let rules = map_local_rules(source);
    if rules.is_empty() {
        return Ok(None);
    }
    match first_match(&rules, url)? {
        Some(found) => Ok(found),
        None => {
            // One refused pattern fails the whole load; retry without the
            // refused ones, which were graded unsupported at import.
            let accepted = rules
                .into_iter()
                .filter(|rule| map_local_pattern_accepted(&rule.pattern))
                .collect::<Vec<_>>();
            Ok(first_match(&accepted, url)?.flatten())
        }
    }
}

/// Matches `url` with the core, using the patterns as request-phase reject
/// rules; the matched pattern names the rule. `None` when the core refuses
/// the patterns.
fn first_match(
    rules: &[LoonMapLocalRule],
    url: &str,
) -> DomainResult<Option<Option<LoonMapLocalRule>>> {
    if rules.is_empty() {
        return Ok(Some(None));
    }
    let mut config = String::from("[Rewrite]\n");
    for rule in rules {
        config.push_str(&quote(&rule.pattern));
        config.push_str(" reject\n");
    }
    let mut engine = AnixOpsMitmPolicyEngine::new()?;
    if engine.load_config(&config).is_err() {
        return Ok(None);
    }
    let result = engine.evaluate_url_rewrite(url, MitmPolicyPhase::Request)?;
    Ok(Some(
        rules
            .iter()
            .find(|rule| result.rule_index >= 0 && rule.pattern == result.matched_pattern)
            .cloned(),
    ))
}

/// True when the core compiles `pattern` as a URL regex.
pub(crate) fn map_local_pattern_accepted(pattern: &str) -> bool {
    let config = format!("[Rewrite]\n{} reject\n", quote(pattern));
    AnixOpsMitmPolicyEngine::new()
        .and_then(|mut engine| engine.load_config(&config))
        .is_ok_and(|report| report.rewrite_rule_count == 1)
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    let mut padding = false;
    for byte in text.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => {
                padding = true;
                continue;
            }
            _ => return None,
        };
        if padding {
            return None;
        }
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_with_and_without_padding() {
        assert_eq!(decode_base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(decode_base64("aGVsbG8").unwrap(), b"hello");
        assert!(decode_base64("aGVs*G8=").is_none());
    }

    #[test]
    fn quoted_patterns_are_skipped_before_attributes() {
        let rule = parse_map_local_line(r#""^https://a\.test/x y" data="ok""#).unwrap();
        assert_eq!(rule.pattern, r"^https://a\.test/x y");
        assert_eq!(rule.body, b"ok");
    }
}
