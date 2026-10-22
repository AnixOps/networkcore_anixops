#![no_main]

//! Drives well-formed HTTP/2 requests with arbitrary methods, paths,
//! authorities, headers, bodies, and trailers through the decrypted HTTP/2
//! MITM session, so the rewrite normalization sees deep inputs.

use engine_native_fuzz::{run_session, send_fuzz_requests, FuzzSession};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|session: FuzzSession| {
    run_session(move |client| send_fuzz_requests(client, session));
});
