#![no_main]

//! Feeds arbitrary bytes after a valid client preface into the decrypted
//! HTTP/2 MITM session, with the built-in reject plugin active.

use engine_native_fuzz::{run_session, H2_CLIENT_PREFACE};
use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fuzz_target!(|data: &[u8]| {
    let frames = data.to_vec();
    run_session(move |mut client| async move {
        let _ = client.write_all(H2_CLIENT_PREFACE).await;
        let _ = client.write_all(&frames).await;
        let _ = client.shutdown().await;
        let mut sink = [0_u8; 4096];
        while matches!(client.read(&mut sink).await, Ok(read) if read > 0) {}
    });
});
