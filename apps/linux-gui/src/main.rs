#[cfg(all(feature = "gui", target_os = "linux"))]
mod app;

#[cfg(all(feature = "gui", target_os = "linux"))]
fn main() {
    if let Err(error) = app::run() {
        eprintln!("anixops-net: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(all(feature = "gui", target_os = "linux")))]
fn main() {
    eprintln!("anixops-net: the window is built on Linux with `--features gui`");
    std::process::exit(1);
}
