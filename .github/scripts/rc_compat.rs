use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

fn option_name(value: &OsString) -> String {
    value.to_string_lossy().to_ascii_lowercase()
}

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    let mut output = None;
    let mut input = None;
    let mut include_dirs = Vec::new();
    let mut defines = Vec::new();

    while let Some(arg) = args.next() {
        let name = option_name(&arg);
        if name == "/fo" {
            output = Some(args.next().expect("rc /fo requires a value"));
        } else if let Some(value) = name.strip_prefix("/fo") {
            output = Some(OsString::from(value));
        } else if name == "/i" {
            include_dirs.push(args.next().expect("rc /I requires a value"));
        } else if name.starts_with("/i") {
            include_dirs.push(OsString::from(&name[2..]));
        } else if name == "/d" {
            defines.push(args.next().expect("rc /D requires a value"));
        } else if name.starts_with("/d") {
            defines.push(OsString::from(&name[2..]));
        } else if name.starts_with('/') {
            continue;
        } else {
            input = Some(arg);
        }
    }

    let output = output.expect("rc requires /fo");
    let input = input.expect("rc requires a resource file");
    let mingw_prefix = PathBuf::from(env::var_os("MINGW_PREFIX").expect("MINGW_PREFIX is required"));
    let windres = mingw_prefix.join("bin").join("windres.exe");
    let mut command = Command::new(windres);
    command
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .arg("--output-format=coff")
        .arg("--target=pe-x86-64");
    for include_dir in include_dirs {
        command.arg("--include-dir").arg(include_dir);
    }
    for define in defines {
        command.arg("--define").arg(define);
    }

    let status = command.status().expect("failed to launch MinGW windres");
    std::process::exit(status.code().unwrap_or(1));
}
