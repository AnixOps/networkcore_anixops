//! Records the first ClientHello a browser sends, for
//! `.github/workflows/browser-fingerprints.yml`.
//!
//! `fp_capture <listen address> <output file> [timeout seconds]` accepts
//! connections until one starts with a ClientHello, writes the handshake
//! message as hex to the output file, answers with a handshake_failure alert
//! and prints the JA3 / JA4 and a profile derived from it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use tls_mimic::ja::{parse_client_hello, spec_from_hello};

fn read_hello(stream: &mut std::net::TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut message = Vec::new();
    loop {
        let mut header = [0u8; 5];
        stream.read_exact(&mut header)?;
        if header[0] != 0x16 {
            return Err(std::io::Error::other("not a handshake record"));
        }
        let mut body = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
        stream.read_exact(&mut body)?;
        message.extend_from_slice(&body);
        if message.len() >= 4 {
            let len = (usize::from(message[1]) << 16)
                | (usize::from(message[2]) << 8)
                | usize::from(message[3]);
            if message.len() >= 4 + len {
                message.truncate(4 + len);
                return Ok(message);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: fp_capture <listen address> <output file> [timeout seconds]");
        std::process::exit(2);
    }
    let timeout = Duration::from_secs(args.get(3).and_then(|s| s.parse().ok()).unwrap_or(120));
    let listener = TcpListener::bind(&args[1]).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            eprintln!("no ClientHello within {timeout:?}");
            std::process::exit(1);
        }
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(error) => panic!("accept: {error}"),
        };
        let _ = stream.set_nonblocking(false);
        let Ok(message) = read_hello(&mut stream) else {
            continue;
        };
        let Ok(hello) = parse_client_hello(&message) else {
            continue;
        };
        // handshake_failure
        let _ = stream.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
        let hex: String = message.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&args[2], format!("{hex}\n")).expect("write capture");
        println!("server_name: {:?}", hello.server_name());
        println!("ja3:  {} ({})", hello.ja3(), hello.ja3_string());
        println!("ja3n: {}", hello.ja3n());
        println!("ja4:  {}", hello.ja4());
        match spec_from_hello(&hello, false) {
            Ok(spec) => println!("profile: {}", spec.to_json()),
            Err(error) => println!("profile: not reproducible by this build: {error}"),
        }
        return;
    }
}
