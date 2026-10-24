//! Points the desktop's proxy settings at the local proxy and puts them back afterwards.
//!
//! GNOME-family desktops read `org.gnome.system.proxy` through `gsettings`; KDE Plasma reads `kioslaverc`
//! through `kwriteconfig6` (or `kwriteconfig5`). Other desktops are reported as unsupported, and the user can
//! point applications at the local address by hand. Only the mode is backed up: the host and port keys the
//! client writes are inert once the mode is back to what it was.

use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Desktop {
    Gnome,
    Kde,
}

impl Desktop {
    /// From `XDG_CURRENT_DESKTOP`, a colon-separated list such as `ubuntu:GNOME`.
    pub fn detect(current_desktop: Option<&str>) -> Option<Self> {
        let value = current_desktop?.to_ascii_lowercase();
        let names: Vec<&str> = value.split(':').collect();
        if names.contains(&"kde") {
            return Some(Self::Kde);
        }
        const GNOME_FAMILY: [&str; 6] = ["gnome", "unity", "cinnamon", "budgie", "pantheon", "x-cinnamon"];
        names.iter().any(|name| GNOME_FAMILY.contains(name)).then_some(Self::Gnome)
    }

    pub fn from_env() -> Option<Self> {
        Self::detect(std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref())
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Gnome => "GNOME",
            Self::Kde => "KDE Plasma",
        }
    }
}

/// The desktop's proxy mode before the client changed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyBackup {
    pub desktop: Desktop,
    /// GNOME: the `mode` string such as `none`. KDE: the `ProxyType` number such as `0`.
    pub previous_mode: String,
}

/// One external command: program and arguments.
pub type Invocation = Vec<String>;

fn invocation(parts: &[&str]) -> Invocation {
    parts.iter().map(|part| part.to_string()).collect()
}

/// Commands that read the current mode, for the backup.
pub fn read_mode_command(desktop: Desktop, kwrite: &str) -> Invocation {
    match desktop {
        Desktop::Gnome => invocation(&["gsettings", "get", "org.gnome.system.proxy", "mode"]),
        Desktop::Kde => invocation(&[
            kwrite.replace("kwrite", "kread").as_str(),
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            "ProxyType",
        ]),
    }
}

/// Parses the output of [`read_mode_command`]; `gsettings` quotes strings.
pub fn parse_mode(desktop: Desktop, output: &str) -> String {
    let value = output.trim().trim_matches('\'').trim();
    match (desktop, value.is_empty()) {
        (Desktop::Gnome, true) => "none".to_string(),
        (Desktop::Kde, true) => "0".to_string(),
        _ => value.to_string(),
    }
}

/// Commands that route HTTP, HTTPS and SOCKS traffic through `127.0.0.1:port` and leave local addresses direct.
pub fn apply_commands(desktop: Desktop, kwrite: &str, port: u16) -> Vec<Invocation> {
    let port = port.to_string();
    match desktop {
        Desktop::Gnome => {
            let mut commands = Vec::new();
            for scheme in ["http", "https", "socks"] {
                let schema = format!("org.gnome.system.proxy.{scheme}");
                commands.push(invocation(&["gsettings", "set", schema.as_str(), "host", "127.0.0.1"]));
                commands.push(invocation(&["gsettings", "set", schema.as_str(), "port", port.as_str()]));
            }
            commands.push(invocation(&[
                "gsettings",
                "set",
                "org.gnome.system.proxy",
                "ignore-hosts",
                "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']",
            ]));
            commands.push(invocation(&["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"]));
            commands
        }
        Desktop::Kde => {
            let http = format!("http://127.0.0.1 {port}");
            let socks = format!("socks://127.0.0.1 {port}");
            let mut commands: Vec<Invocation> = [
                ("httpProxy", http.as_str()),
                ("httpsProxy", http.as_str()),
                ("socksProxy", socks.as_str()),
                ("NoProxyFor", "localhost,127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"),
                ("ProxyType", "1"),
            ]
            .iter()
            .map(|(key, value)| kde_write(kwrite, key, value))
            .collect();
            commands.push(kde_reload());
            commands
        }
    }
}

/// Commands that put the mode back.
pub fn restore_commands(backup: &ProxyBackup, kwrite: &str) -> Vec<Invocation> {
    match backup.desktop {
        Desktop::Gnome => vec![invocation(&[
            "gsettings",
            "set",
            "org.gnome.system.proxy",
            "mode",
            backup.previous_mode.as_str(),
        ])],
        Desktop::Kde => vec![kde_write(kwrite, "ProxyType", backup.previous_mode.as_str()), kde_reload()],
    }
}

fn kde_write(kwrite: &str, key: &str, value: &str) -> Invocation {
    invocation(&[kwrite, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, value])
}

/// Tells running KDE applications to reread their proxy settings.
fn kde_reload() -> Invocation {
    invocation(&[
        "dbus-send",
        "--type=signal",
        "/KIO/Scheduler",
        "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
        "string:",
    ])
}

/// `kwriteconfig6` on Plasma 6, else `kwriteconfig5`.
pub fn kwrite_program() -> &'static str {
    let found = |name: &str| {
        std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
            .unwrap_or(false)
    };
    if found("kwriteconfig6") {
        "kwriteconfig6"
    } else {
        "kwriteconfig5"
    }
}

fn run(command: &Invocation) -> Result<String, String> {
    let (program, arguments) = command.split_first().ok_or("empty command")?;
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("{program} could not run: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Backs up the current mode and applies the proxy. On failure the desktop is left as it was as far as possible.
pub fn apply(desktop: Desktop, port: u16) -> Result<ProxyBackup, String> {
    let kwrite = kwrite_program();
    let previous = run(&read_mode_command(desktop, kwrite))?;
    let backup = ProxyBackup {
        desktop,
        previous_mode: parse_mode(desktop, &previous),
    };
    for command in apply_commands(desktop, kwrite, port) {
        if let Err(error) = run(&command) {
            let _ = restore(&backup);
            return Err(error);
        }
    }
    Ok(backup)
}

pub fn restore(backup: &ProxyBackup) -> Result<(), String> {
    let kwrite = kwrite_program();
    let mut first_error = None;
    for command in restore_commands(backup, kwrite) {
        if let Err(error) = run(&command) {
            // The reload signal is best effort; the setting itself is what matters.
            if command.first().map(String::as_str) != Some("dbus-send") {
                first_error.get_or_insert(error);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_desktops_from_the_environment_value() {
        assert_eq!(Desktop::detect(Some("ubuntu:GNOME")), Some(Desktop::Gnome));
        assert_eq!(Desktop::detect(Some("X-Cinnamon")), Some(Desktop::Gnome));
        assert_eq!(Desktop::detect(Some("KDE")), Some(Desktop::Kde));
        assert_eq!(Desktop::detect(Some("XFCE")), None);
        assert_eq!(Desktop::detect(None), None);
    }

    #[test]
    fn gnome_commands_set_every_scheme_then_switch_the_mode() {
        let commands = apply_commands(Desktop::Gnome, "kwriteconfig6", 7890);
        assert!(commands.contains(&invocation(&["gsettings", "set", "org.gnome.system.proxy.socks", "port", "7890"])));
        assert_eq!(
            commands.last().unwrap(),
            &invocation(&["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"]),
            "the mode switches only after the addresses are in place"
        );
        let backup = ProxyBackup {
            desktop: Desktop::Gnome,
            previous_mode: parse_mode(Desktop::Gnome, "'auto'\n"),
        };
        assert_eq!(
            restore_commands(&backup, "kwriteconfig6"),
            vec![invocation(&["gsettings", "set", "org.gnome.system.proxy", "mode", "auto"])]
        );
    }

    #[test]
    fn kde_commands_use_the_found_tool_and_reload() {
        let commands = apply_commands(Desktop::Kde, "kwriteconfig5", 1080);
        assert!(commands.iter().all(|command| command[0] == "kwriteconfig5" || command[0] == "dbus-send"));
        assert!(commands.iter().any(|command| command.last().unwrap() == "http://127.0.0.1 1080"));
        assert_eq!(read_mode_command(Desktop::Kde, "kwriteconfig5")[0], "kreadconfig5");
        assert_eq!(parse_mode(Desktop::Kde, ""), "0");
        let restore = restore_commands(
            &ProxyBackup {
                desktop: Desktop::Kde,
                previous_mode: "0".to_string(),
            },
            "kwriteconfig6",
        );
        assert_eq!(restore[0].last().unwrap(), "0");
    }
}
