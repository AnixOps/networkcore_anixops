//! Each fingerprint against its target: a ClientHello captured from the real
//! browser must have the same JA4 and sorted-extension JA3 (JA3N) as the one
//! this crate builds for the same server name and ALPN, and the same JA3 when
//! the browser does not permute its extensions.
//!
//! Committed captures (`tests/data/<profile>-<version>.hex`) are checked on
//! every run. `captured_browsers_match_profiles` checks fresh ones from
//! `.github/workflows/browser-fingerprints.yml` (`TLS_MIMIC_CAPTURES`, one
//! `<profile>.hex` per browser) and prints a profile for any that differ.

use std::fmt::Write as _;
use std::path::Path;

use tls_mimic::fingerprint::build_from_spec;
use tls_mimic::ja::{decode_hex, parse_client_hello, spec_from_hello, Hello};
use tls_mimic::Fingerprint;

struct Row {
    profile: &'static str,
    source: String,
    target: Hello,
    ours: Hello,
    permuted: bool,
}

impl Row {
    fn matches(&self) -> bool {
        self.target.ja4() == self.ours.ja4()
            && self.target.ja3n() == self.ours.ja3n()
            && (self.permuted || self.target.ja3() == self.ours.ja3())
    }
}

/// The fingerprint a capture file is for: the longest profile name it
/// starts with.
fn profile_of(file_stem: &str) -> Option<Fingerprint> {
    Fingerprint::ALL
        .into_iter()
        .filter(|fingerprint| {
            let name = fingerprint.name();
            file_stem == name || file_stem.starts_with(&format!("{name}-"))
        })
        .max_by_key(|fingerprint| fingerprint.name().len())
}

fn compare(fingerprint: Fingerprint, source: String, capture: &str) -> Row {
    let target = parse_client_hello(&decode_hex(capture).unwrap()).unwrap();
    let spec = fingerprint.spec().unwrap();
    let server_name = target.server_name().unwrap_or_default();
    let alpn = target.alpn();
    let built = build_from_spec(&spec, &server_name, Some(&alpn)).unwrap();
    Row {
        profile: fingerprint.name(),
        source,
        target,
        ours: parse_client_hello(&built.message).unwrap(),
        permuted: spec.permute_extensions,
    }
}

fn report(rows: &[Row]) -> String {
    let mut out = String::from(
        "| profile | capture | JA4 (browser) | JA4 (ours) | JA3N (browser) | JA3N (ours) | JA3 (browser) | JA3 (ours) | result |\n\
         |---|---|---|---|---|---|---|---|---|\n",
    );
    for row in rows {
        let ja3 = |hello: &Hello| {
            if row.permuted {
                "permuted".to_owned()
            } else {
                hello.ja3()
            }
        };
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | {} |",
            row.profile,
            row.source,
            row.target.ja4(),
            row.ours.ja4(),
            row.target.ja3n(),
            row.ours.ja3n(),
            ja3(&row.target),
            ja3(&row.ours),
            if row.matches() {
                "match"
            } else {
                "**differs**"
            },
        );
    }
    out
}

fn check(rows: Vec<Row>) {
    let table = report(&rows);
    println!("{table}");
    if let Ok(summary) = std::env::var("GITHUB_STEP_SUMMARY") {
        let mut text = std::fs::read_to_string(&summary).unwrap_or_default();
        text.push_str("\n### tls-mimic fingerprints vs captured browsers\n\n");
        text.push_str(&table);
        let _ = std::fs::write(&summary, text);
    }
    let mut failed = Vec::new();
    for row in &rows {
        if row.matches() {
            continue;
        }
        println!("--- {} ({}) differs", row.profile, row.source);
        println!("browser ja3: {}", row.target.ja3_string());
        println!("ours    ja3: {}", row.ours.ja3_string());
        match spec_from_hello(&row.target, row.permuted) {
            Ok(spec) => println!("profile from the capture: {}", spec.to_json()),
            Err(error) => println!("the capture cannot be reproduced by this build: {error}"),
        }
        failed.push(format!("{} ({})", row.profile, row.source));
    }
    assert!(failed.is_empty(), "fingerprints differ: {failed:?}");
}

fn captures_in(dir: &Path, require_profile: bool) -> Vec<Row> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "hex"))
        .collect();
    entries.sort();
    let mut rows = Vec::new();
    for path in entries {
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        let fingerprint = match profile_of(&stem) {
            Some(fingerprint) => fingerprint,
            None if require_profile => panic!("{stem}: no fingerprint of that name"),
            None => {
                // A browser without a profile yet: print what one would be.
                let capture = std::fs::read_to_string(&path).unwrap();
                let hello = parse_client_hello(&decode_hex(&capture).unwrap()).unwrap();
                println!("--- {stem} has no profile; ja4 {}", hello.ja4());
                match spec_from_hello(&hello, false) {
                    Ok(spec) => println!("profile from the capture: {}", spec.to_json()),
                    Err(error) => println!("cannot be reproduced by this build: {error}"),
                }
                continue;
            }
        };
        let capture = std::fs::read_to_string(&path).unwrap();
        rows.push(compare(fingerprint, stem, &capture));
    }
    rows
}

#[test]
fn committed_captures_match_their_profiles() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let rows = captures_in(&dir, true);
    assert!(!rows.is_empty());
    check(rows);
}

#[test]
#[ignore = "needs TLS_MIMIC_CAPTURES from the browser-fingerprints workflow"]
fn captured_browsers_match_profiles() {
    let dir = std::env::var("TLS_MIMIC_CAPTURES").expect("TLS_MIMIC_CAPTURES");
    let rows = captures_in(Path::new(&dir), false);
    check(rows);
}
