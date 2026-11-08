//! Coverage report over public Loon, Surge and Quantumult X plugins (M-A0).
//!
//! `tests/fixtures/public-corpus/manifest.tsv` pins each plugin to a commit and a
//! SHA-256. The plugin files themselves are not committed: the `MITM plugin
//! corpus` workflow downloads them with `.github/scripts/fetch-mitm-corpus.sh`
//! and runs this test with `MITM_PUBLIC_CORPUS_DIR` pointing at the download.
//! Without it only the manifest is checked.
//!
//! With `MITM_PUBLIC_CORPUS_REPORT` set, the Markdown report is also written to
//! that file (the workflow appends it to the job summary).
//!
//! Map Local data is fetched by the App when a plugin is imported. The
//! workflow does the same in two passes: with `MITM_PUBLIC_CORPUS_DATA_LIST`
//! set the test only writes the data URLs it finds, one per line; the workflow
//! downloads them into `MITM_PUBLIC_CORPUS_DATA_DIR` as `<n>` files listed in
//! `index.tsv` (`<n>\t<url>`), and the graded pass hands them to
//! `import_loon_plugin_with_resources`. The data URLs are not pinned; one that
//! fails to download stays graded `map_local.remote_data_missing`.

use mitm_policy::loon_plugin::{
    import_loon_plugin, import_loon_plugin_with_resources, LoonLineStatus, LoonRemoteResourceKind,
    LoonSupportLevel,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

struct Entry {
    id: String,
    dialect: String,
    repo: String,
    commit: String,
    path: String,
}

struct Manifest {
    entries: Vec<Entry>,
    min_full_percent: usize,
}

fn manifest() -> Manifest {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public-corpus/manifest.tsv");
    let text = std::fs::read_to_string(path).expect("corpus manifest should be readable");
    let mut entries = Vec::new();
    let mut min_full_percent = None;
    for line in text.lines() {
        if let Some(gate) = line.strip_prefix("#! min-full-percent ") {
            min_full_percent = Some(gate.trim().parse().expect("gate should be a number"));
            continue;
        }
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = line.split('\t').collect();
        assert_eq!(columns.len(), 6, "manifest line needs 6 columns: {line}");
        let is_hex = |value: &str, len: usize| {
            value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
        };
        assert!(is_hex(columns[3], 40), "commit must be a full SHA: {line}");
        assert!(
            is_hex(columns[5], 64),
            "sha256 must be 64 hex digits: {line}"
        );
        assert!(
            matches!(columns[1], "loon" | "surge" | "qx"),
            "dialect must be loon, surge or qx: {line}"
        );
        entries.push(Entry {
            id: columns[0].to_string(),
            dialect: columns[1].to_string(),
            repo: columns[2].to_string(),
            commit: columns[3].to_string(),
            path: columns[4].to_string(),
        });
    }
    Manifest {
        entries,
        min_full_percent: min_full_percent.expect("manifest needs a min-full-percent gate"),
    }
}

#[test]
fn public_corpus_manifest_is_well_formed() {
    let manifest = manifest();
    assert!(
        manifest.entries.len() >= 30,
        "M-A0 asks for at least 30 plugins"
    );
    assert!(manifest.min_full_percent <= 100);
    let ids: BTreeSet<&str> = manifest.entries.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids.len(), manifest.entries.len(), "ids must be unique");
    for entry in &manifest.entries {
        assert!(
            entry
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "id must be a lower-case file name: {}",
            entry.id
        );
        assert!(entry.id.starts_with(&format!("{}-", entry.dialect)));
    }
}

/// Downloaded Map Local data by URL (see the module docs).
fn downloaded_data() -> BTreeMap<String, Vec<u8>> {
    let Some(dir) = std::env::var_os("MITM_PUBLIC_CORPUS_DATA_DIR") else {
        return BTreeMap::new();
    };
    let dir = Path::new(&dir);
    let Ok(index) = std::fs::read_to_string(dir.join("index.tsv")) else {
        return BTreeMap::new();
    };
    index
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter_map(|(file, url)| {
            std::fs::read(dir.join(file))
                .ok()
                .map(|bytes| (url.to_string(), bytes))
        })
        .collect()
}

#[derive(Default)]
struct ReasonCount {
    lines: usize,
    plugins: BTreeSet<String>,
}

#[test]
fn public_corpus_coverage_report() {
    let Some(dir) = std::env::var_os("MITM_PUBLIC_CORPUS_DIR") else {
        println!("MITM_PUBLIC_CORPUS_DIR is not set; run the MITM plugin corpus workflow");
        return;
    };
    let dir = Path::new(&dir);
    let manifest = manifest();
    let data_list = std::env::var_os("MITM_PUBLIC_CORPUS_DATA_LIST");
    let data = downloaded_data();
    let mut data_urls = BTreeSet::new();

    let mut rows = String::new();
    let mut levels: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_dialect: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut reasons: BTreeMap<(String, &'static str), ReasonCount> = BTreeMap::new();
    let mut errors: BTreeMap<String, ReasonCount> = BTreeMap::new();

    for entry in &manifest.entries {
        let text = std::fs::read(dir.join(&entry.id))
            .unwrap_or_else(|error| panic!("{} was not fetched: {error}", entry.id));
        let text = String::from_utf8_lossy(&text);
        let source = format!(
            "[{}](https://github.com/{}/blob/{}/{})",
            entry.id, entry.repo, entry.commit, entry.path
        );
        let dialect = by_dialect.entry(entry.dialect.as_str()).or_default();
        dialect.0 += 1;
        let imported = if data.is_empty() {
            import_loon_plugin(&text)
        } else {
            import_loon_plugin_with_resources(&text, &data)
        };
        match imported {
            Ok(plugin) => {
                data_urls.extend(
                    plugin
                        .remote_resources
                        .iter()
                        .filter(|r| r.kind == LoonRemoteResourceKind::MapLocalData)
                        .map(|r| r.url.clone()),
                );
                let report = &plugin.report;
                let level = report.level.as_str();
                *levels.entry(level).or_default() += 1;
                if report.level == LoonSupportLevel::Full {
                    dialect.1 += 1;
                }
                let scripts = plugin
                    .remote_resources
                    .iter()
                    .filter(|r| r.kind == LoonRemoteResourceKind::Script)
                    .count();
                let data = plugin.remote_resources.len() - scripts;
                let _ = writeln!(
                    rows,
                    "| {source} | {} | {level} | {} | {} | {} | {} | {} | {scripts} | {data} |",
                    entry.dialect,
                    plugin.mitm_hostnames.include.len(),
                    report.count(LoonLineStatus::Supported),
                    report.count(LoonLineStatus::Partial),
                    report.count(LoonLineStatus::Deferred),
                    report.count(LoonLineStatus::Unsupported),
                );
                println!("{}", report.render_text(&entry.id));
                if let Some(error) = &report.policy_load_error {
                    let count = errors.entry(format!("policy core: {error}")).or_default();
                    count.lines += 1;
                    count.plugins.insert(entry.id.clone());
                }
                for line in &report.lines {
                    if matches!(
                        line.status,
                        LoonLineStatus::Supported | LoonLineStatus::Ignored
                    ) {
                        continue;
                    }
                    let count = reasons
                        .entry((line.reason.clone(), line.status.as_str()))
                        .or_default();
                    count.lines += 1;
                    count.plugins.insert(entry.id.clone());
                }
            }
            Err(error) => {
                *levels.entry("error").or_default() += 1;
                let _ = writeln!(
                    rows,
                    "| {source} | {} | error: `{}` | | | | | | | |",
                    entry.dialect, error.code
                );
                println!(
                    "{}: import error {}: {}",
                    entry.id, error.code, error.message
                );
                let count = errors.entry(error.code.clone()).or_default();
                count.lines += 1;
                count.plugins.insert(entry.id.clone());
            }
        }
    }

    if let Some(path) = data_list {
        let mut list = data_urls.into_iter().collect::<Vec<_>>().join("\n");
        list.push('\n');
        std::fs::write(path, list).expect("data list should be writable");
        return;
    }

    let total = manifest.entries.len();
    let full = levels.get("full").copied().unwrap_or(0);
    let full_percent = full * 100 / total;

    let mut report = String::new();
    let _ = writeln!(report, "## MITM public plugin corpus\n");
    let _ = writeln!(
        report,
        "{total} plugins: full {full} ({full_percent}%), partial {}, unsupported {}, import errors {}. Gate: full >= {}%. Map Local data downloaded: {}.\n",
        levels.get("partial").copied().unwrap_or(0),
        levels.get("unsupported").copied().unwrap_or(0),
        levels.get("error").copied().unwrap_or(0),
        manifest.min_full_percent,
        data.len(),
    );
    let _ = writeln!(report, "| Dialect | Plugins | Full |\n|---|---|---|");
    for (dialect, (count, full)) in &by_dialect {
        let _ = writeln!(report, "| {dialect} | {count} | {full} |");
    }
    let mut ranked: Vec<_> = reasons.into_iter().collect();
    ranked.sort_by(|a, b| {
        b.1.plugins
            .len()
            .cmp(&a.1.plugins.len())
            .then(b.1.lines.cmp(&a.1.lines))
            .then(a.0.cmp(&b.0))
    });
    let _ = writeln!(
        report,
        "\n### Lines not fully supported, by how many plugins they affect\n\n| Reason | Status | Plugins | Lines |\n|---|---|---|---|"
    );
    for ((reason, status), count) in &ranked {
        let _ = writeln!(
            report,
            "| `{reason}` | {status} | {} | {} |",
            count.plugins.len(),
            count.lines
        );
    }
    if !errors.is_empty() {
        let _ = writeln!(
            report,
            "\n### Plugins refused\n\n| Error | Plugins |\n|---|---|"
        );
        for (code, count) in &errors {
            let names: Vec<&str> = count.plugins.iter().map(String::as_str).collect();
            let _ = writeln!(report, "| `{code}` | {} |", names.join(", "));
        }
    }
    let _ = writeln!(
        report,
        "\n### Plugins\n\n| Plugin | Dialect | Level | Hosts | Supported | Partial | Deferred | Unsupported | Scripts | Remote data |\n|---|---|---|---|---|---|---|---|---|---|\n{rows}"
    );

    println!("{report}");
    if let Some(path) = std::env::var_os("MITM_PUBLIC_CORPUS_REPORT") {
        std::fs::write(path, &report).expect("report should be writable");
    }
    assert!(
        full_percent >= manifest.min_full_percent,
        "full coverage {full_percent}% fell below the {}% gate",
        manifest.min_full_percent
    );
}
