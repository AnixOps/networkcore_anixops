//! "Start after login" through an XDG autostart entry, which every mainstream desktop reads.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "anixops-net.desktop";

/// `$XDG_CONFIG_HOME/autostart`, else `~/.config/autostart`.
pub fn autostart_dir() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(config.join("autostart"))
}

/// The desktop entry that starts `executable`.
pub fn entry(executable: &Path) -> String {
    // Desktop entry Exec values quote arguments with double quotes and escape `"`, `` ` ``, `$` and `\`.
    let escaped: String = executable
        .to_string_lossy()
        .chars()
        .flat_map(|character| match character {
            '"' | '`' | '$' | '\\' => vec!['\\', character],
            other => vec![other],
        })
        .collect();
    format!(
        "[Desktop Entry]\nType=Application\nName=AnixOps Net\nExec=\"{escaped}\"\nIcon=anixops-net\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    )
}

pub fn set_enabled(dir: &Path, enabled: bool, executable: &Path) -> io::Result<()> {
    let path = dir.join(FILE_NAME);
    if enabled {
        fs::create_dir_all(dir)?;
        fs::write(path, entry(executable))
    } else {
        match fs::remove_file(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }
}

pub fn is_enabled(dir: &Path) -> bool {
    dir.join(FILE_NAME).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_quotes_the_executable() {
        let text = entry(Path::new("/opt/AnixOps Net/anixops-$net"));
        assert!(text.contains("Exec=\"/opt/AnixOps Net/anixops-\\$net\"\n"));
        assert!(text.starts_with("[Desktop Entry]\n"));
    }

    #[test]
    fn enabling_writes_and_disabling_removes_the_entry() {
        let dir = std::env::temp_dir().join(format!("anixops-net-autostart-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        set_enabled(&dir, true, Path::new("/usr/bin/anixops-net")).unwrap();
        assert!(is_enabled(&dir));
        set_enabled(&dir, false, Path::new("/usr/bin/anixops-net")).unwrap();
        assert!(!is_enabled(&dir));
        set_enabled(&dir, false, Path::new("/usr/bin/anixops-net")).unwrap();
        let _ = fs::remove_dir_all(dir);
    }
}
