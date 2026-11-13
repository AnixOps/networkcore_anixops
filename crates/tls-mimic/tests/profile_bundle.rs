//! Installing a delivered fingerprint bundle. The override table is process
//! wide, so this lives in its own test binary and in a single test.

use tls_mimic::fingerprint::is_grease;
use tls_mimic::{
    build_client_hello, clear_profiles, install_profiles, installed_profiles, Fingerprint,
};

fn cipher_suites(message: &[u8]) -> Vec<u16> {
    // header(4) version(2) random(32) session id (1 + 32)
    let pos = 4 + 2 + 32 + 1 + 32;
    let len = u16::from_be_bytes([message[pos], message[pos + 1]]) as usize;
    message[pos + 2..pos + 2 + len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|suite| !is_grease(*suite))
        .collect()
}

fn suites_of(fingerprint: Fingerprint) -> Vec<u16> {
    cipher_suites(
        &build_client_hello(fingerprint, "example.com", None)
            .unwrap()
            .message,
    )
}

#[test]
fn a_bundle_replaces_built_in_fingerprints_until_cleared() {
    let chrome = suites_of(Fingerprint::Chrome);
    let safari = suites_of(Fingerprint::Safari);
    assert_eq!(chrome.len(), 15);
    assert_eq!(safari.len(), 20);
    assert_eq!(&safari[..3], &[0x1302, 0x1303, 0x1301]);

    // A "next Chrome" that drops the CBC suites, plus a profile for a
    // fingerprint this build does not have.
    let mut next: serde_json::Value =
        serde_json::from_str(&Fingerprint::Chrome.builtin_spec().unwrap().to_json()).unwrap();
    next["cipher_suites"] = serde_json::json!(["grease", "0x1301", "0x1302", "0x1303", "0xc02b"]);
    let bundle = serde_json::json!({
        "format": 1,
        "revision": "test-1",
        "profiles": { "chrome": next, "some-future-browser": { "anything": true } },
    })
    .to_string();
    let installed = install_profiles(&bundle).unwrap();
    assert_eq!(installed.revision, "test-1");
    assert_eq!(installed.replaced, [Fingerprint::Chrome]);
    assert_eq!(installed.ignored, ["some-future-browser"]);
    assert_eq!(installed_profiles().revision, "test-1");
    assert_eq!(installed_profiles().replaced, [Fingerprint::Chrome]);
    assert_eq!(
        suites_of(Fingerprint::Chrome),
        [0x1301, 0x1302, 0x1303, 0xc02b]
    );
    // Fingerprints the bundle does not name keep their built-in spec, and the
    // built-in Chrome is still there to fall back to.
    assert_eq!(suites_of(Fingerprint::Safari), safari);
    assert_eq!(
        Fingerprint::Chrome
            .builtin_spec()
            .unwrap()
            .cipher_suites
            .len(),
        16
    );

    // A bundle with a broken known profile changes nothing.
    for broken in [
        r#"{"format": 1, "profiles": {"safari": {"cipher_suites": [], "extensions": []}}}"#,
        r#"{"format": 2, "profiles": {}}"#,
        r#"{"format": 1, "profiles": {}, "extra": 1}"#,
        "not json",
    ] {
        assert!(install_profiles(broken).is_err(), "{broken}");
        assert_eq!(
            suites_of(Fingerprint::Chrome),
            [0x1301, 0x1302, 0x1303, 0xc02b]
        );
        assert_eq!(suites_of(Fingerprint::Safari), safari);
    }

    // A bundle is the whole override state: one that only names Safari puts
    // Chrome back on its built-in spec.
    let nopq: serde_json::Value =
        serde_json::from_str(&Fingerprint::ChromeNoPq.builtin_spec().unwrap().to_json()).unwrap();
    let only_safari =
        serde_json::json!({ "format": 1, "profiles": { "safari": nopq } }).to_string();
    let installed = install_profiles(&only_safari).unwrap();
    assert_eq!(installed.replaced, [Fingerprint::Safari]);
    assert_eq!(suites_of(Fingerprint::Chrome), chrome);
    assert_eq!(suites_of(Fingerprint::Safari), chrome);

    clear_profiles();
    assert!(installed_profiles().replaced.is_empty());
    assert_eq!(suites_of(Fingerprint::Safari), safari);
}
