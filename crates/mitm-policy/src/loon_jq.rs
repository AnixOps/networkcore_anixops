//! jq body rewrites (`http-response-jq`, `response-body-jq`, Quantumult X
//! `jsonjq-response-body`, ...) run with jaq, a jq implementation in Rust.
//!
//! The `mitm_anixops` core is built without libjq. It still parses the
//! importer's `<url> response-body-jq <filter>` lines, matches them in the
//! body chain and leaves the body alone with the message
//! [`JQ_BACKEND_UNAVAILABLE`]. Those steps run here afterwards, in chain
//! order, on the body the core produced. The filter is read back from the
//! loaded source because the core's result value is capped at 2 KiB.

use crate::loon_syntax::tokens;
use crate::{MitmPolicyBodyRewriteChain, MitmPolicyPhase};
use jaq_core::load::{Arena, File, Loader};
use jaq_core::{data, unwrap_valr, Compiler, Ctx, Vars};
use jaq_json::{read, Val};
use std::collections::BTreeMap;

/// Message of a jq step the core matched but could not run.
pub const JQ_BACKEND_UNAVAILABLE: &str = "jq backend unavailable";

/// Bodies larger than this are left alone.
pub const JQ_MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

/// Runs `filter` on the JSON `body` and returns the first output as compact
/// JSON. `None` when the body is not JSON, the filter does not compile, or it
/// fails or yields nothing; the body is then left unchanged, as jq-capable
/// clients do.
pub fn run_jq(filter: &str, body: &str) -> Option<String> {
    if body.len() > JQ_MAX_INPUT_BYTES {
        return None;
    }
    let input = read::parse_single(body.trim().as_bytes()).ok()?;
    let defs = jaq_core::defs()
        .chain(jaq_std::defs())
        .chain(jaq_json::defs());
    let funs = jaq_core::funs()
        .chain(jaq_std::funs())
        .chain(jaq_json::funs());
    let loader = Loader::new(defs);
    let arena = Arena::default();
    let modules = loader
        .load(
            &arena,
            File {
                code: filter,
                path: (),
            },
        )
        .ok()?;
    let compiled = Compiler::default().with_funs(funs).compile(modules).ok()?;
    let ctx = Ctx::<data::JustLut<Val>>::new(&compiled.lut, Vars::new([]));
    let mut outputs = compiled.id.run((ctx, input)).map(unwrap_valr);
    let first = outputs.next()?.ok()?;
    Some(first.to_string())
}

/// `<pattern> request-body-jq|response-body-jq <filter>` lines of a loaded
/// policy source, in order.
fn jq_rules(source: &str) -> Vec<(String, MitmPolicyPhase, String)> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';', '[']) {
                return None;
            }
            let parts = tokens(line);
            if parts.len() < 3 {
                return None;
            }
            let phase = match parts[1].to_ascii_lowercase().as_str() {
                "request-body-jq" => MitmPolicyPhase::Request,
                "response-body-jq" => MitmPolicyPhase::Response,
                _ => return None,
            };
            Some((parts[0].clone(), phase, parts[2].clone()))
        })
        .collect()
}

/// Runs the jq steps of `chain` on `body`. `None` when no jq step changed it.
pub fn apply_jq_steps(
    source: &str,
    phase: MitmPolicyPhase,
    chain: &MitmPolicyBodyRewriteChain,
    body: &str,
) -> Option<String> {
    let steps = chain
        .rewrites
        .iter()
        .filter(|step| step.message == JQ_BACKEND_UNAVAILABLE)
        .collect::<Vec<_>>();
    if steps.is_empty() {
        return None;
    }
    let rules = jq_rules(source);
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    let mut current = body.to_string();
    let mut changed = false;
    for step in steps {
        let nth = seen.entry(step.matched_pattern.as_str()).or_default();
        let filter = rules
            .iter()
            .filter(|(pattern, rule_phase, _)| {
                *pattern == step.matched_pattern && *rule_phase == phase
            })
            .nth(*nth)
            .map(|(_, _, filter)| filter.as_str())
            .unwrap_or(step.value.as_str());
        *nth += 1;
        if let Some(output) = run_jq(filter, &current) {
            changed |= output != current;
            current = output;
        }
    }
    changed.then_some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_used_by_published_plugins_run() {
        assert_eq!(
            run_jq("del(.data.payment)", r#"{"data":{"payment":1,"a":2}}"#).as_deref(),
            Some(r#"{"data":{"a":2}}"#)
        );
        assert_eq!(
            run_jq(
                r#".data.modules |= map(select(.type != "TIP"))"#,
                r#"{"data":{"modules":[{"type":"TIP"},{"type":"A"}]}}"#
            )
            .as_deref(),
            Some(r#"{"data":{"modules":[{"type":"A"}]}}"#)
        );
        assert_eq!(
            run_jq(r#"delpaths([["a","b"]])"#, r#"{"a":{"b":1,"c":2}}"#).as_deref(),
            Some(r#"{"a":{"c":2}}"#)
        );
        assert_eq!(
            run_jq(
                r#".data[][]?="stun.example.com:3478""#,
                r#"{"data":{"x":["a","b"]}}"#
            )
            .as_deref(),
            Some(r#"{"data":{"x":["stun.example.com:3478","stun.example.com:3478"]}}"#)
        );
        assert_eq!(
            run_jq(
                r#"if .vip then .vip.status = 1 else . end | .x |= (. // 0)"#,
                r#"{"vip":{"status":0}}"#
            )
            .as_deref(),
            Some(r#"{"vip":{"status":1},"x":0}"#)
        );
        assert_eq!(run_jq(".a", "not json"), None);
        assert_eq!(run_jq("syntax error (", "{}"), None);
    }
}
