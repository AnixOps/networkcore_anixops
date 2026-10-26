//! Which local process opened a connection to the desktop local proxy, for
//! `PROCESS-NAME` rules.
//!
//! The client's socket is the TCP connection whose local address is the
//! peer address the proxy accepted and whose remote address is the proxy's
//! own: on Linux it is found in `/proc/net/tcp{,6}` and its inode in
//! `/proc/<pid>/fd`, on Windows in the `GetExtendedTcpTable` owner-PID table,
//! and on macOS among every process's socket descriptors (`proc_pidfdinfo`).
//! The name is the executable's file name (`curl`, `chrome.exe`, `Telegram`),
//! which `PROCESS-NAME` matches without regard to case. Processes the engine
//! may not inspect (another user's, without privileges) give no name, so
//! their connections skip `PROCESS-NAME` rules. Names are only used for
//! routing and the connection list, never logged.
//!
//! A lookup reads kernel tables and, on Linux and macOS, walks every
//! process's descriptors, so it blocks: callers run it on a blocking thread
//! and only for configs that have `PROCESS-NAME` rules.

use std::net::SocketAddr;

/// The executable name of the process whose TCP socket has local address
/// `client` and is connected to `server`.
pub fn process_name(client: SocketAddr, server: SocketAddr) -> Option<String> {
    let client = canonical(client);
    let server = canonical(server);
    platform::process_name(client, server)
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The last path component of an executable path.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "windows", target_os = "macos")),
    allow(dead_code)
)]
fn file_name(path: &std::path::Path) -> Option<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const TCP_TABLES: [&str; 2] = ["/proc/net/tcp", "/proc/net/tcp6"];

    pub fn process_name(client: SocketAddr, server: SocketAddr) -> Option<String> {
        let inode = TCP_TABLES
            .iter()
            .find_map(|table| socket_inode(table, client, server))?;
        let pid = owner_pid(inode)?;
        fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|path| super::file_name(&path))
            .or_else(|| {
                fs::read_to_string(format!("/proc/{pid}/comm"))
                    .ok()
                    .map(|comm| comm.trim().to_string())
                    .filter(|comm| !comm.is_empty())
            })
    }

    /// The inode of the socket from `client` to `server` in one of the
    /// `/proc/net` TCP tables.
    fn socket_inode(table: &str, client: SocketAddr, server: SocketAddr) -> Option<u64> {
        let text = fs::read_to_string(table).ok()?;
        text.lines().skip(1).find_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 10 {
                return None;
            }
            let local = parse_socket(fields[1])?;
            let remote = parse_socket(fields[2])?;
            if super::canonical(local) != client || super::canonical(remote) != server {
                return None;
            }
            fields[9].parse::<u64>().ok().filter(|inode| *inode != 0)
        })
    }

    /// `0100007F:1F90`: the address as the kernel's 32-bit words in host
    /// order, then the port.
    pub(super) fn parse_socket(text: &str) -> Option<SocketAddr> {
        let (address, port) = text.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let word = |index: usize| {
            address
                .get(index * 8..index * 8 + 8)
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .map(u32::to_ne_bytes)
        };
        let ip = match address.len() {
            8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
            32 => {
                let mut bytes = [0u8; 16];
                for index in 0..4 {
                    bytes[index * 4..index * 4 + 4].copy_from_slice(&word(index)?);
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    /// The process holding a descriptor for socket `inode`.
    fn owner_pid(inode: u64) -> Option<u32> {
        let link = format!("socket:[{inode}]");
        fs::read_dir("/proc").ok()?.flatten().find_map(|entry| {
            let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
            let descriptors = fs::read_dir(entry.path().join("fd")).ok()?;
            descriptors
                .flatten()
                .any(|fd| {
                    fs::read_link(fd.path()).is_ok_and(|target| target.as_os_str() == link.as_str())
                })
                .then_some(pid)
        })
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const NO_ERROR: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    /// `MIB_TCPROW_OWNER_PID` and `MIB_TCP6ROW_OWNER_PID` sizes.
    const ROW_V4: usize = 24;
    const ROW_V6: usize = 56;

    pub fn process_name(client: SocketAddr, server: SocketAddr) -> Option<String> {
        let pid = if client.is_ipv4() {
            owner_pid(AF_INET, client, server)
        } else {
            owner_pid(AF_INET6, client, server)
        }?;
        image_name(pid)
    }

    /// The owning process of the connection from `client` to `server` in
    /// the owner-PID TCP table of `family`.
    fn owner_pid(family: u32, client: SocketAddr, server: SocketAddr) -> Option<u32> {
        let table = tcp_table(family)?;
        let count = usize::try_from(read_u32(&table, 0)?).ok()?;
        let row_size = if family == AF_INET { ROW_V4 } else { ROW_V6 };
        // The rows follow the DWORD entry count.
        (0..count).find_map(|index| {
            let row = table.get(4 + index * row_size..4 + (index + 1) * row_size)?;
            let (local, remote, pid) = if family == AF_INET {
                (
                    v4_socket(&row[4..8], &row[8..12])?,
                    v4_socket(&row[12..16], &row[16..20])?,
                    read_u32(row, 20)?,
                )
            } else {
                (
                    v6_socket(&row[0..16], &row[20..24])?,
                    v6_socket(&row[24..40], &row[44..48])?,
                    read_u32(row, 52)?,
                )
            };
            (super::canonical(local) == client && super::canonical(remote) == server).then_some(pid)
        })
    }

    fn tcp_table(family: u32) -> Option<Vec<u8>> {
        let mut size = 0u32;
        for _ in 0..4 {
            // u32 storage keeps the table's DWORD alignment.
            let mut buffer = vec![0u32; (size as usize).div_ceil(4)];
            // SAFETY: `buffer` has room for `size` bytes and `size` is a valid
            // pointer; the call writes at most `size` bytes or reports the
            // size it needs.
            let result = unsafe {
                GetExtendedTcpTable(
                    buffer.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            match result {
                NO_ERROR => {
                    let bytes = buffer.iter().flat_map(|word| word.to_ne_bytes()).collect();
                    return Some(bytes);
                }
                ERROR_INSUFFICIENT_BUFFER => continue,
                _ => return None,
            }
        }
        None
    }

    fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
        let word = bytes.get(at..at + 4)?;
        Some(u32::from_ne_bytes(word.try_into().ok()?))
    }

    /// The address and port fields hold network byte order in memory.
    fn v4_socket(address: &[u8], port: &[u8]) -> Option<SocketAddr> {
        let address: [u8; 4] = address.try_into().ok()?;
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(address)),
            u16::from_be_bytes([port[0], port[1]]),
        ))
    }

    fn v6_socket(address: &[u8], port: &[u8]) -> Option<SocketAddr> {
        let address: [u8; 16] = address.try_into().ok()?;
        Some(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(address)),
            u16::from_be_bytes([port[0], port[1]]),
        ))
    }

    fn image_name(pid: u32) -> Option<String> {
        // SAFETY: plain call; a null handle means no access.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; 1024];
        let mut length = buffer.len() as u32;
        // SAFETY: `process` is an open handle, `buffer` holds `length` UTF-16
        // units and `length` is a valid pointer.
        let ok = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                buffer.as_mut_ptr(),
                &mut length,
            )
        };
        // SAFETY: `process` was opened above and is closed once.
        unsafe { CloseHandle(process) };
        if ok == 0 {
            return None;
        }
        buffer.truncate(length as usize);
        let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer));
        super::file_name(&path)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::ffi::OsStrExt;

    /// `PROC_PIDFDSOCKETINFO` from `sys/proc_info.h`.
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    /// `SOCKINFO_TCP`.
    const SOCKINFO_TCP: i32 = 2;
    /// `INI_IPV4` / `INI_IPV6` in `insi_vflag`.
    const INI_IPV4: u8 = 0x1;
    const INI_IPV6: u8 = 0x2;
    /// Offsets in `struct socket_fdinfo`: `proc_fileinfo` is 24 bytes, then
    /// `socket_info` with `vinfo_stat` (136 bytes) first; `soi_kind` is at
    /// 232 and the `soi_proto` union, whose TCP and IP members both start
    /// with `struct in_sockinfo`, at 240.
    const SOI_KIND: usize = 24 + 232;
    const IN_SOCKINFO: usize = 24 + 240;
    const INSI_FPORT: usize = IN_SOCKINFO;
    const INSI_LPORT: usize = IN_SOCKINFO + 4;
    const INSI_VFLAG: usize = IN_SOCKINFO + 24;
    const INSI_FADDR: usize = IN_SOCKINFO + 32;
    const INSI_LADDR: usize = IN_SOCKINFO + 48;
    /// Larger than the kernel's `struct socket_fdinfo` (792 bytes), which
    /// only requires the buffer to be at least that big.
    const SOCKET_FDINFO_BUFFER: usize = 1280;

    pub fn process_name(client: SocketAddr, server: SocketAddr) -> Option<String> {
        let pid = all_pids().into_iter().find(|pid| {
            descriptors(*pid)
                .into_iter()
                .any(|fd| socket_matches(*pid, fd, client, server))
        })?;
        let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `path` holds the given number of bytes.
        let length = unsafe {
            libc::proc_pidpath(pid, path.as_mut_ptr().cast::<c_void>(), path.len() as u32)
        };
        if length <= 0 {
            return None;
        }
        path.truncate(length as usize);
        super::file_name(std::path::Path::new(std::ffi::OsStr::from_bytes(&path)))
    }

    fn all_pids() -> Vec<i32> {
        // SAFETY: a null buffer asks for the number of processes.
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0i32; count as usize + 64];
        let bytes = (pids.len() * size_of::<i32>()) as i32;
        // SAFETY: `pids` holds `bytes` bytes.
        let count = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        pids.truncate(count.max(0) as usize);
        pids.retain(|pid| *pid > 0);
        pids
    }

    /// The socket descriptors of `pid`.
    fn descriptors(pid: i32) -> Vec<i32> {
        // SAFETY: a null buffer asks for the size of the descriptor list.
        let size =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if size <= 0 {
            return Vec::new();
        }
        // Each `struct proc_fdinfo` is an i32 descriptor and a u32 type.
        let mut entries = vec![0i32; size as usize / 4 + 32];
        let bytes = (entries.len() * 4) as i32;
        // SAFETY: `entries` holds `bytes` bytes.
        let size = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                bytes,
            )
        };
        entries.truncate(size.max(0) as usize / 4);
        entries
            .chunks_exact(2)
            .filter(|entry| entry[1] == libc::PROX_FDTYPE_SOCKET)
            .map(|entry| entry[0])
            .collect()
    }

    fn socket_matches(pid: i32, fd: i32, client: SocketAddr, server: SocketAddr) -> bool {
        // u64 storage keeps the struct's 8-byte alignment.
        let mut buffer = vec![0u64; SOCKET_FDINFO_BUFFER / 8];
        // SAFETY: `buffer` holds SOCKET_FDINFO_BUFFER bytes.
        let size = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd,
                PROC_PIDFDSOCKETINFO,
                buffer.as_mut_ptr().cast(),
                SOCKET_FDINFO_BUFFER as i32,
            )
        };
        if size <= 0 {
            return false;
        }
        let bytes = buffer
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .collect::<Vec<_>>();
        let i32_at = |at: usize| {
            i32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        if i32_at(SOI_KIND) != SOCKINFO_TCP {
            return false;
        }
        // The ports are stored in network byte order.
        let port_at = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        let address_at = |at: usize| -> Option<IpAddr> {
            match bytes[INSI_VFLAG] {
                flag if flag & INI_IPV6 != 0 => {
                    let address: [u8; 16] = bytes[at..at + 16].try_into().ok()?;
                    Some(IpAddr::V6(Ipv6Addr::from(address)))
                }
                flag if flag & INI_IPV4 != 0 => {
                    let address: [u8; 4] = bytes[at + 12..at + 16].try_into().ok()?;
                    Some(IpAddr::V4(Ipv4Addr::from(address)))
                }
                _ => None,
            }
        };
        let (Some(local), Some(remote)) = (address_at(INSI_LADDR), address_at(INSI_FADDR)) else {
            return false;
        };
        let local = SocketAddr::new(local.to_canonical(), port_at(INSI_LPORT));
        let remote = SocketAddr::new(remote.to_canonical(), port_at(INSI_FPORT));
        local == client && remote == server
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
mod platform {
    use std::net::SocketAddr;

    pub fn process_name(_client: SocketAddr, _server: SocketAddr) -> Option<String> {
        None
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::platform::parse_socket;

    #[test]
    fn proc_net_tcp_addresses_parse() {
        let local = parse_socket("0100007F:1F90").unwrap();
        assert_eq!(local.to_string(), "127.0.0.1:8080");
        let local = parse_socket("00000000000000000000000001000000:0050").unwrap();
        assert_eq!(local.to_string(), "[::1]:80");
        assert!(parse_socket("zz:1").is_none());
    }
}
