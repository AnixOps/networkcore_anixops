use std::env;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    let mut forwarded = Vec::new();

    while let Some(arg) = args.next() {
        if arg == OsStr::new("--target") {
            let target = args.next().expect("windres --target requires a value");
            forwarded.push(OsString::from(format!(
                "--target={}",
                target.to_string_lossy()
            )));
        } else {
            forwarded.push(arg);
        }
    }

    let mingw_prefix = PathBuf::from(env::var_os("MINGW_PREFIX").expect("MINGW_PREFIX is required"));
    let windres = mingw_prefix.join("bin").join("windres.exe");
    let status = Command::new(windres)
        .args(forwarded)
        .status()
        .expect("failed to launch MinGW windres");

    std::process::exit(status.code().unwrap_or(1));
}
