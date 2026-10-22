#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let protocols = engine_native::observe_tls_client_hello_alpn_protocols(data);
    assert!(protocols.iter().all(|protocol| !protocol.is_empty()));
});
