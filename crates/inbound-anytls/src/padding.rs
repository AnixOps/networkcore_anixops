//! The padding scheme a server hands its clients.
//!
//! A client pads its first packets as the scheme says and reports the MD5 of
//! the scheme it has in its settings; the server answers a different MD5
//! with its own scheme. The server itself does not pad.

use engine_inbound::registry::BuildError;
use md5::{Digest, Md5};

/// The scheme clients start with; a server with this scheme sends none.
pub const DEFAULT_PADDING_SCHEME: &[&str] = &[
    "stop=8",
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaddingScheme {
    raw: Vec<u8>,
    md5: String,
}

impl PaddingScheme {
    /// A scheme from its lines (`stop=N`, then `packet=min-max,...`).
    /// Clients refuse a scheme without an integer `stop`, so it is refused
    /// here too.
    pub fn new<S: AsRef<str>>(lines: &[S]) -> Result<Self, BuildError> {
        let raw = lines
            .iter()
            .map(|line| line.as_ref())
            .collect::<Vec<_>>()
            .join("\n");
        let has_stop = raw
            .split('\n')
            .filter_map(|line| line.split_once('='))
            .any(|(key, value)| key == "stop" && value.parse::<i64>().is_ok());
        if !has_stop {
            return Err("anytls padding_scheme needs a stop=N line");
        }
        let md5 = Md5::digest(raw.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(Self {
            raw: raw.into_bytes(),
            md5,
        })
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Lowercase hex, as clients report it.
    pub fn md5(&self) -> &str {
        &self.md5
    }
}

impl Default for PaddingScheme {
    fn default() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME).expect("the default scheme is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_matches_the_clients() {
        let scheme = PaddingScheme::default();
        assert!(scheme.raw().starts_with(b"stop=8\n0=30-30\n"));
        assert!(scheme.raw().ends_with(b"\n7=500-1000"));
        assert_eq!(scheme.md5().len(), 32);
        assert_ne!(PaddingScheme::new(&["stop=4"]).unwrap(), scheme);
        assert!(PaddingScheme::new(&["0=30-30"]).is_err());
        assert!(PaddingScheme::new(&["stop=x"]).is_err());
    }
}
