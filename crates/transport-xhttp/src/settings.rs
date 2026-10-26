//! The `"transport": {"type": "xhttp", ...}` object, with Xray's field names
//! accepted as aliases so an `xhttpSettings` block can be pasted as is.

use std::collections::BTreeMap;
use std::io;

use ring::rand::{SecureRandom, SystemRandom};
use serde::de::{self, Deserializer};
use serde::Deserialize;

/// Padding length range of every request (`x_padding`), Xray's default.
pub const DEFAULT_PADDING_BYTES: Range = Range::new(100, 1000);
/// Largest body of one `packet-up` upload, Xray's default.
pub const DEFAULT_MAX_EACH_POST_BYTES: Range = Range::fixed(1_000_000);
/// Least time between two `packet-up` uploads, Xray's default.
pub const DEFAULT_MIN_POSTS_INTERVAL_MS: Range = Range::fixed(30);
/// Smallest accepted `sc_max_each_post_bytes`.
pub const MIN_EACH_POST_BYTES: u32 = 1024;

/// How the upload direction travels; the download is always one streaming
/// response.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// `packet-up`, as Xray picks for TLS and plain connections.
    #[default]
    Auto,
    /// Numbered `POST {path}{session}/{seq}` requests, reordered by the
    /// server; works through any HTTP proxy or CDN.
    PacketUp,
    /// One long streaming `POST {path}{session}` next to the download `GET`.
    StreamUp,
    /// One `POST {path}` whose request body is the upload and whose response
    /// body is the download.
    StreamOne,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PacketUp => "packet-up",
            Self::StreamUp => "stream-up",
            Self::StreamOne => "stream-one",
        }
    }
}

/// A closed range of which every use takes a random value, written as a
/// number, `"from-to"`, or `{"from": .., "to": ..}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub from: u32,
    pub to: u32,
}

impl Range {
    pub const fn new(from: u32, to: u32) -> Self {
        Self { from, to }
    }

    pub const fn fixed(value: u32) -> Self {
        Self::new(value, value)
    }

    /// `"100-1000"` or `"30"`; `None` when malformed or `from > to`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let range = match text.split_once('-') {
            Some((from, to)) => Self::new(from.trim().parse().ok()?, to.trim().parse().ok()?),
            None => Self::fixed(text.parse().ok()?),
        };
        range.is_valid().then_some(range)
    }

    pub fn is_valid(&self) -> bool {
        self.from <= self.to
    }

    pub fn contains(&self, value: usize) -> bool {
        (self.from as usize..=self.to as usize).contains(&value)
    }

    /// A uniformly random value in the range.
    pub fn sample(&self) -> u32 {
        if self.from >= self.to {
            return self.from;
        }
        let span = u64::from(self.to - self.from) + 1;
        self.from + (u64::from_le_bytes(random_bytes()) % span) as u32
    }
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Number(u32),
            Text(String),
            Object { from: u32, to: u32 },
        }
        let range = match Repr::deserialize(deserializer)? {
            Repr::Number(value) => Some(Range::fixed(value)),
            Repr::Text(text) => Range::parse(&text),
            Repr::Object { from, to } => Some(Range::new(from, to)).filter(Range::is_valid),
        };
        range.ok_or_else(|| {
            de::Error::custom("range must be a number or \"from-to\" with from <= to")
        })
    }
}

/// XHTTP settings shared by the client and the server.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XhttpSettings {
    /// Request path prefix, optionally with a query; normalized to start and
    /// end with `/`.
    #[serde(default)]
    pub path: String,
    /// `Host` (HTTP/1.1) or `:authority` (HTTP/2); the client defaults to
    /// the TLS server name or the server address, and the server accepts any
    /// host when empty.
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub mode: Mode,
    /// Extra request headers sent by the client.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_padding", alias = "xPaddingBytes")]
    pub x_padding_bytes: Range,
    #[serde(default = "default_max_each_post", alias = "scMaxEachPostBytes")]
    pub sc_max_each_post_bytes: Range,
    #[serde(default = "default_min_posts_interval", alias = "scMinPostsIntervalMs")]
    pub sc_min_posts_interval_ms: Range,
    /// Leaves out `Content-Type: application/grpc` on streaming uploads,
    /// which some CDNs need to pass the request body through unbuffered.
    #[serde(default, alias = "noGRPCHeader")]
    pub no_grpc_header: bool,
}

impl Default for XhttpSettings {
    fn default() -> Self {
        Self {
            path: String::new(),
            host: String::new(),
            mode: Mode::Auto,
            headers: BTreeMap::new(),
            x_padding_bytes: DEFAULT_PADDING_BYTES,
            sc_max_each_post_bytes: DEFAULT_MAX_EACH_POST_BYTES,
            sc_min_posts_interval_ms: DEFAULT_MIN_POSTS_INTERVAL_MS,
            no_grpc_header: false,
        }
    }
}

fn default_padding() -> Range {
    DEFAULT_PADDING_BYTES
}

fn default_max_each_post() -> Range {
    DEFAULT_MAX_EACH_POST_BYTES
}

fn default_min_posts_interval() -> Range {
    DEFAULT_MIN_POSTS_INTERVAL_MS
}

impl XhttpSettings {
    /// The path without its query, starting and ending with `/`.
    pub fn normalized_path(&self) -> String {
        let path = self.path.split('?').next().unwrap_or_default();
        let mut normalized = String::with_capacity(path.len() + 2);
        if !path.starts_with('/') {
            normalized.push('/');
        }
        normalized.push_str(path);
        if !normalized.ends_with('/') {
            normalized.push('/');
        }
        normalized
    }

    /// The query after `?` in `path`, empty when there is none.
    pub fn query(&self) -> &str {
        self.path.split_once('?').map_or("", |(_, query)| query)
    }

    /// Checks what both sides rely on: a usable path and query, and ranges
    /// the transport can work with.
    pub fn validate(&self) -> io::Result<()> {
        let path = self.normalized_path();
        if !path.bytes().all(is_path_byte) || path.contains("//") {
            return Err(invalid("xhttp path is invalid"));
        }
        if !self
            .query()
            .bytes()
            .all(|byte| is_path_byte(byte) || byte == b'?')
        {
            return Err(invalid("xhttp path query is invalid"));
        }
        if self.sc_max_each_post_bytes.from < MIN_EACH_POST_BYTES {
            return Err(invalid("xhttp sc_max_each_post_bytes is too small"));
        }
        if self.x_padding_bytes.to > 64 * 1024 {
            return Err(invalid("xhttp x_padding_bytes is too large"));
        }
        Ok(())
    }
}

/// Unreserved and sub-delimiter characters, `:`, `@`, `/` and `%` escapes.
fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/%".contains(&byte)
}

/// A random version 4 UUID in its hyphenated text form, the session id.
pub fn session_id() -> String {
    let mut bytes: [u8; 16] = random_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut text = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    // The system generator does not fail on supported platforms; zeros only
    // weaken the padding and session id, not the proxied protocol.
    let _ = SystemRandom::new().fill(&mut bytes);
    bytes
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_parse_in_every_form() {
        assert_eq!(Range::parse("100-1000"), Some(Range::new(100, 1000)));
        assert_eq!(Range::parse(" 30 "), Some(Range::fixed(30)));
        assert_eq!(Range::parse("9-3"), None);
        assert_eq!(Range::parse("a-3"), None);
        let settings: XhttpSettings = serde_json::from_str(
            r#"{"path": "/xh", "mode": "stream-one", "xPaddingBytes": "10-20",
                "sc_max_each_post_bytes": 500000, "scMinPostsIntervalMs": {"from": 5, "to": 9}}"#,
        )
        .unwrap();
        assert_eq!(settings.mode, Mode::StreamOne);
        assert_eq!(settings.x_padding_bytes, Range::new(10, 20));
        assert_eq!(settings.sc_max_each_post_bytes, Range::fixed(500_000));
        assert_eq!(settings.sc_min_posts_interval_ms, Range::new(5, 9));
        assert!(serde_json::from_str::<XhttpSettings>(r#"{"xPaddingBytes": "9-1"}"#).is_err());
        assert!(serde_json::from_str::<XhttpSettings>(r#"{"mode": "packet"}"#).is_err());
        assert!(serde_json::from_str::<XhttpSettings>(r#"{"paht": "/"}"#).is_err());
        for _ in 0..100 {
            assert!(Range::new(100, 1000).contains(Range::new(100, 1000).sample() as usize));
        }
    }

    #[test]
    fn paths_are_normalized_and_checked() {
        let settings = |path: &str| XhttpSettings {
            path: path.into(),
            ..XhttpSettings::default()
        };
        assert_eq!(settings("").normalized_path(), "/");
        assert_eq!(settings("xh").normalized_path(), "/xh/");
        assert_eq!(settings("/a/b/?ed=2048").normalized_path(), "/a/b/");
        assert_eq!(settings("/a/b/?ed=2048").query(), "ed=2048");
        assert!(settings("/a/b?x=1").validate().is_ok());
        for bad in ["/a b", "/a\r\n", "/a//b", "/a?x=\"", "/ü"] {
            assert!(settings(bad).validate().is_err(), "{bad:?}");
        }
        let small = XhttpSettings {
            sc_max_each_post_bytes: Range::fixed(100),
            ..XhttpSettings::default()
        };
        assert!(small.validate().is_err());
    }

    #[test]
    fn session_ids_are_version_4_uuids() {
        let id = session_id();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert_eq!(id.matches('-').count(), 4);
        assert_ne!(id, session_id());
    }
}
