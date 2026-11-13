//! The ANX license context (anx spec §2.4.1). Its own test binary: the
//! context is process-wide.

use node_import::{import_text, set_anx_license, AnxLicense};

fn anx_outbound() -> serde_json::Value {
    let key = "ab".repeat(32);
    let report = import_text(&format!(
        "anx://{key}@203.0.113.7:8443?sni=www.apple.com&pk=aa%3Abb#JP%20ANX"
    ))
    .unwrap();
    report.nodes[0].outbound.clone()
}

#[test]
fn anx_outbounds_carry_the_license_only_once_set() {
    let plain = anx_outbound();
    for key in ["device_key", "device_alg", "license_cert_path"] {
        assert!(plain.get(key).is_none(), "{key} without a license");
    }

    set_anx_license(Some(AnxLicense {
        device_key: "3051".into(),
        device_alg: "ed25519".into(),
        license_cert_path: "/var/lib/anixops-net/anx/license.cert".into(),
    }));
    let licensed = anx_outbound();
    assert_eq!(licensed["device_key"], "3051");
    assert_eq!(licensed["device_alg"], "ed25519");
    assert_eq!(
        licensed["license_cert_path"],
        "/var/lib/anixops-net/anx/license.cert"
    );
    // Through the C ABI, as the iOS app sets it.
    let json = br#"{"device_key":"30","device_alg":"p256","license_cert_path":"/x"}"#;
    let code =
        unsafe { node_import::ffi::networkcore_import_set_anx_license(json.as_ptr(), json.len()) };
    assert_eq!(code, node_import::ffi::NETWORKCORE_IMPORT_OK);
    assert_eq!(anx_outbound()["device_alg"], "p256");
    let bad = b"{}";
    let code =
        unsafe { node_import::ffi::networkcore_import_set_anx_license(bad.as_ptr(), bad.len()) };
    assert_eq!(
        code,
        node_import::ffi::NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT
    );
    let code = unsafe { node_import::ffi::networkcore_import_set_anx_license(std::ptr::null(), 0) };
    assert_eq!(code, node_import::ffi::NETWORKCORE_IMPORT_OK);
    assert!(anx_outbound().get("device_key").is_none());
}
