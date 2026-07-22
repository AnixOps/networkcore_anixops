//! Native Windows service, proxy, certificate, and driver integration.

use crate::managed::{WindowsProxySettings, WindowsProxySnapshot};
use control_domain::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const NETWORKCORE_WINDOWS_SERVICE_NAME: &str = "AnixOpsNetworkCore";
pub const NETWORKCORE_WINDOWS_SERVICE_DISPLAY_NAME: &str = "AnixOps NetworkCore";
pub const NETWORKCORE_WINDOWS_SERVICE_DESCRIPTION: &str =
    "Manages the AnixOps NetworkCore tunnel and Windows network integration.";

pub const WINDOWS_SERVICE_OPERATION_FAILED_CODE: &str = "windows.service.operation_failed";
pub const WINDOWS_PROXY_OPERATION_FAILED_CODE: &str = "windows.proxy.operation_failed";
pub const WINDOWS_CERTIFICATE_OPERATION_FAILED_CODE: &str = "windows.certificate.operation_failed";
pub const WINDOWS_DRIVER_OPERATION_FAILED_CODE: &str = "windows.driver.operation_failed";
pub const WINDOWS_PLATFORM_REQUIRED_CODE: &str = "windows.platform.required";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    Running,
    StopPending,
    Paused,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsServiceStatus {
    pub state: WindowsServiceState,
    pub process_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsDriverInstallResult {
    pub inf_path: PathBuf,
    pub reboot_required: bool,
}

pub trait WindowsSystemIntegration {
    fn install_service(&self, executable: &Path) -> DomainResult<()>;
    fn uninstall_service(&self) -> DomainResult<()>;
    fn start_service(&self) -> DomainResult<WindowsServiceStatus>;
    fn stop_service(&self) -> DomainResult<WindowsServiceStatus>;
    fn restart_service(&self) -> DomainResult<WindowsServiceStatus>;
    fn service_status(&self) -> DomainResult<WindowsServiceStatus>;
    fn apply_system_proxy(
        &self,
        settings: &WindowsProxySettings,
    ) -> DomainResult<WindowsProxySnapshot>;
    fn restore_system_proxy(&self, snapshot: &WindowsProxySnapshot) -> DomainResult<()>;
    fn install_root_certificate(&self, certificate: &Path) -> DomainResult<String>;
    fn remove_root_certificate(&self, sha1_thumbprint: &str) -> DomainResult<()>;
    fn install_driver(&self, inf_path: &Path) -> DomainResult<WindowsDriverInstallResult>;
    fn uninstall_driver(&self, inf_path: &Path) -> DomainResult<bool>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeWindowsSystemIntegration;

impl NativeWindowsSystemIntegration {
    pub const fn new() -> Self {
        Self
    }
}

impl WindowsSystemIntegration for NativeWindowsSystemIntegration {
    fn install_service(&self, executable: &Path) -> DomainResult<()> {
        native::install_service(executable)
    }

    fn uninstall_service(&self) -> DomainResult<()> {
        native::uninstall_service()
    }

    fn start_service(&self) -> DomainResult<WindowsServiceStatus> {
        native::start_service()
    }

    fn stop_service(&self) -> DomainResult<WindowsServiceStatus> {
        native::stop_service()
    }

    fn restart_service(&self) -> DomainResult<WindowsServiceStatus> {
        native::stop_service()?;
        native::start_service()
    }

    fn service_status(&self) -> DomainResult<WindowsServiceStatus> {
        native::service_status()
    }

    fn apply_system_proxy(
        &self,
        settings: &WindowsProxySettings,
    ) -> DomainResult<WindowsProxySnapshot> {
        settings.validate()?;
        native::apply_system_proxy(settings)
    }

    fn restore_system_proxy(&self, snapshot: &WindowsProxySnapshot) -> DomainResult<()> {
        native::restore_system_proxy(snapshot)
    }

    fn install_root_certificate(&self, certificate: &Path) -> DomainResult<String> {
        native::install_root_certificate(certificate)
    }

    fn remove_root_certificate(&self, sha1_thumbprint: &str) -> DomainResult<()> {
        native::remove_root_certificate(sha1_thumbprint)
    }

    fn install_driver(&self, inf_path: &Path) -> DomainResult<WindowsDriverInstallResult> {
        native::install_driver(inf_path)
    }

    fn uninstall_driver(&self, inf_path: &Path) -> DomainResult<bool> {
        native::uninstall_driver(inf_path)
    }
}

#[cfg(not(windows))]
mod native {
    use super::*;

    fn unsupported() -> DomainError {
        DomainError::new(
            WINDOWS_PLATFORM_REQUIRED_CODE,
            "this operation requires Windows",
        )
    }

    pub fn install_service(_executable: &Path) -> DomainResult<()> {
        Err(unsupported())
    }

    pub fn uninstall_service() -> DomainResult<()> {
        Err(unsupported())
    }

    pub fn start_service() -> DomainResult<WindowsServiceStatus> {
        Err(unsupported())
    }

    pub fn stop_service() -> DomainResult<WindowsServiceStatus> {
        Err(unsupported())
    }

    pub fn service_status() -> DomainResult<WindowsServiceStatus> {
        Err(unsupported())
    }

    pub fn apply_system_proxy(
        _settings: &WindowsProxySettings,
    ) -> DomainResult<WindowsProxySnapshot> {
        Err(unsupported())
    }

    pub fn restore_system_proxy(_snapshot: &WindowsProxySnapshot) -> DomainResult<()> {
        Err(unsupported())
    }

    pub fn install_root_certificate(_certificate: &Path) -> DomainResult<String> {
        Err(unsupported())
    }

    pub fn remove_root_certificate(_sha1_thumbprint: &str) -> DomainResult<()> {
        Err(unsupported())
    }

    pub fn install_driver(_inf_path: &Path) -> DomainResult<WindowsDriverInstallResult> {
        Err(unsupported())
    }

    pub fn uninstall_driver(_inf_path: &Path) -> DomainResult<bool> {
        Err(unsupported())
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::ffi::c_void;
    use std::fs;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use std::thread;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
        DiInstallDriverW, DiUninstallDriverW, SetupCopyOEMInfW, DIIRFLAG_INF_ALREADY_COPIED,
        SPOST_PATH,
    };
    use windows_sys::Win32::Foundation::{
        GetLastError, GlobalFree, ERROR_FILE_NOT_FOUND, ERROR_SERVICE_ALREADY_RUNNING,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS, ERROR_SERVICE_NOT_ACTIVE,
        ERROR_SUCCESS,
    };
    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpGetDefaultProxyConfiguration, WinHttpSetDefaultProxyConfiguration,
        WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_PROXY_INFO,
    };
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CertAddCertificateContextToStore, CertCloseStore, CertDeleteCertificateFromStore,
        CertFindCertificateInStore, CertFreeCertificateContext, CertGetCertificateContextProperty,
        CertOpenStore, CryptQueryObject, CERT_CONTEXT, CERT_FIND_SHA1_HASH,
        CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_ALL, CERT_QUERY_OBJECT_FILE,
        CERT_SHA1_HASH_PROP_ID, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_MAXIMUM_ALLOWED_FLAG,
        CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE,
        CRYPT_INTEGER_BLOB, X509_ASN_ENCODING,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
    };
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
        CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
        StartServiceW, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
        SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
        SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE,
        SERVICE_PAUSED, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
        SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
        SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_WIN32_OWN_PROCESS,
    };

    const INTERNET_SETTINGS_KEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const SERVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

    struct ServiceHandle(SC_HANDLE);

    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }

    struct RegistryKey(HKEY);

    impl Drop for RegistryKey {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    pub fn install_service(executable: &Path) -> DomainResult<()> {
        let executable = fs::canonicalize(executable)
            .map_err(|_| service_error("service executable could not be resolved"))?;
        let command = format!("\"{}\" service", executable.display());
        let command = wide(&command);
        let service_name = wide(NETWORKCORE_WINDOWS_SERVICE_NAME);
        let display_name = wide(NETWORKCORE_WINDOWS_SERVICE_DISPLAY_NAME);
        let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;

        let mut service = unsafe {
            CreateServiceW(
                manager.0,
                service_name.as_ptr(),
                display_name.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                command.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
            )
        };
        if service.is_null() {
            let error = unsafe { GetLastError() };
            if error != ERROR_SERVICE_EXISTS {
                return Err(service_win32_error("service could not be installed", error));
            }
            service = unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_ALL_ACCESS) };
            if service.is_null() {
                return Err(last_service_error("installed service could not be opened"));
            }
            let changed = unsafe {
                ChangeServiceConfigW(
                    service,
                    SERVICE_NO_CHANGE,
                    SERVICE_AUTO_START,
                    SERVICE_NO_CHANGE,
                    command.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                    display_name.as_ptr(),
                )
            };
            if changed == 0 {
                unsafe {
                    CloseServiceHandle(service);
                }
                return Err(last_service_error(
                    "service configuration could not be updated",
                ));
            }
        }
        let service = ServiceHandle(service);
        let mut description_text = wide(NETWORKCORE_WINDOWS_SERVICE_DESCRIPTION);
        let description = SERVICE_DESCRIPTIONW {
            lpDescription: description_text.as_mut_ptr(),
        };
        let changed = unsafe {
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_DESCRIPTION,
                &description as *const _ as *const c_void,
            )
        };
        if changed == 0 {
            return Err(last_service_error(
                "service description could not be configured",
            ));
        }
        Ok(())
    }

    pub fn uninstall_service() -> DomainResult<()> {
        let status = service_status()?;
        if status.state == WindowsServiceState::NotInstalled {
            return Ok(());
        }
        if status.state != WindowsServiceState::Stopped {
            stop_service()?;
        }
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_service(manager.0, SERVICE_ALL_ACCESS)?;
        if unsafe { DeleteService(service.0) } == 0 {
            return Err(last_service_error("service could not be removed"));
        }
        Ok(())
    }

    pub fn start_service() -> DomainResult<WindowsServiceStatus> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_service(manager.0, SERVICE_START | SERVICE_QUERY_STATUS)?;
        if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_SERVICE_ALREADY_RUNNING {
                return Err(service_win32_error("service could not be started", error));
            }
        }
        wait_for_service_state(&service, WindowsServiceState::Running)
    }

    pub fn stop_service() -> DomainResult<WindowsServiceStatus> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_service(manager.0, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
        let current = query_service(&service)?;
        if current.state == WindowsServiceState::Stopped {
            return Ok(current);
        }
        let mut status: SERVICE_STATUS = unsafe { zeroed() };
        if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_SERVICE_NOT_ACTIVE {
                return Err(service_win32_error("service could not be stopped", error));
            }
        }
        wait_for_service_state(&service, WindowsServiceState::Stopped)
    }

    pub fn service_status() -> DomainResult<WindowsServiceStatus> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let name = wide(NETWORKCORE_WINDOWS_SERVICE_NAME);
        let raw = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
        if raw.is_null() {
            let error = unsafe { GetLastError() };
            if error == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(WindowsServiceStatus {
                    state: WindowsServiceState::NotInstalled,
                    process_id: 0,
                });
            }
            return Err(service_win32_error(
                "service status could not be opened",
                error,
            ));
        }
        query_service(&ServiceHandle(raw))
    }

    pub fn apply_system_proxy(
        settings: &WindowsProxySettings,
    ) -> DomainResult<WindowsProxySnapshot> {
        let key = open_internet_settings_key()?;
        let mut snapshot = WindowsProxySnapshot {
            enabled: read_registry_dword(&key, "ProxyEnable")? != 0,
            server: read_registry_string(&key, "ProxyServer")?,
            bypass: read_registry_string(&key, "ProxyOverride")?,
            winhttp_access_type: WINHTTP_ACCESS_TYPE_NO_PROXY,
            winhttp_server: String::new(),
            winhttp_bypass: String::new(),
        };
        read_winhttp_snapshot(&mut snapshot)?;

        write_registry_dword(&key, "ProxyEnable", u32::from(settings.enabled))?;
        write_registry_string(&key, "ProxyServer", &settings.server)?;
        write_registry_string(&key, "ProxyOverride", &settings.bypass)?;
        set_winhttp_proxy(settings.enabled, &settings.server, &settings.bypass)?;
        notify_proxy_change()?;
        Ok(snapshot)
    }

    pub fn restore_system_proxy(snapshot: &WindowsProxySnapshot) -> DomainResult<()> {
        let key = open_internet_settings_key()?;
        write_registry_dword(&key, "ProxyEnable", u32::from(snapshot.enabled))?;
        write_registry_string(&key, "ProxyServer", &snapshot.server)?;
        write_registry_string(&key, "ProxyOverride", &snapshot.bypass)?;
        set_winhttp_proxy(
            snapshot.winhttp_access_type == WINHTTP_ACCESS_TYPE_NAMED_PROXY,
            &snapshot.winhttp_server,
            &snapshot.winhttp_bypass,
        )?;
        notify_proxy_change()
    }

    pub fn install_root_certificate(certificate: &Path) -> DomainResult<String> {
        let certificate = fs::canonicalize(certificate)
            .map_err(|_| certificate_error("certificate file could not be resolved"))?;
        let certificate_path = wide_os(certificate.as_os_str());
        let mut context: *mut c_void = null_mut();
        let loaded = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                certificate_path.as_ptr() as *const c_void,
                CERT_QUERY_CONTENT_FLAG_CERT,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut context,
            )
        };
        if loaded == 0 || context.is_null() {
            return Err(last_certificate_error(
                "certificate file could not be decoded",
            ));
        }
        let certificate_context = context as *mut CERT_CONTEXT;
        let store = match open_root_store() {
            Ok(store) => store,
            Err(error) => {
                unsafe {
                    CertFreeCertificateContext(certificate_context);
                }
                return Err(error);
            }
        };
        let added = unsafe {
            CertAddCertificateContextToStore(
                store,
                certificate_context,
                CERT_STORE_ADD_REPLACE_EXISTING,
                null_mut(),
            )
        };
        if added == 0 {
            unsafe {
                CertFreeCertificateContext(certificate_context);
                CertCloseStore(store, 0);
            }
            return Err(last_certificate_error(
                "certificate could not be added to ROOT",
            ));
        }
        let thumbprint = certificate_sha1(certificate_context);
        unsafe {
            CertFreeCertificateContext(certificate_context);
            CertCloseStore(store, 0);
        }
        thumbprint
    }

    pub fn remove_root_certificate(sha1_thumbprint: &str) -> DomainResult<()> {
        let mut hash = parse_sha1(sha1_thumbprint)?;
        let blob = CRYPT_INTEGER_BLOB {
            cbData: hash.len() as u32,
            pbData: hash.as_mut_ptr(),
        };
        let store = open_root_store()?;
        let context = unsafe {
            CertFindCertificateInStore(
                store,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_SHA1_HASH,
                &blob as *const _ as *const c_void,
                null(),
            )
        };
        if context.is_null() {
            unsafe {
                CertCloseStore(store, 0);
            }
            return Ok(());
        }
        let deleted = unsafe { CertDeleteCertificateFromStore(context) };
        unsafe {
            CertCloseStore(store, 0);
        }
        if deleted == 0 {
            return Err(last_certificate_error(
                "certificate could not be removed from ROOT",
            ));
        }
        Ok(())
    }

    pub fn install_driver(inf_path: &Path) -> DomainResult<WindowsDriverInstallResult> {
        let inf_path = fs::canonicalize(inf_path)
            .map_err(|_| driver_error("driver INF could not be resolved"))?;
        let source_path = wide_os(inf_path.as_os_str());
        let mut published_path = vec![0u16; 32_768];
        let mut required_size = 0;
        if unsafe {
            SetupCopyOEMInfW(
                source_path.as_ptr(),
                null(),
                SPOST_PATH,
                0,
                published_path.as_mut_ptr(),
                published_path.len() as u32,
                &mut required_size,
                null_mut(),
            )
        } == 0
        {
            return Err(last_driver_error("driver package could not be staged"));
        }
        let path_length = published_path
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(published_path.len());
        let published_path =
            PathBuf::from(String::from_utf16_lossy(&published_path[..path_length]));
        let published_path_wide = wide_os(published_path.as_os_str());
        let mut reboot_required = 0;
        if unsafe {
            DiInstallDriverW(
                null_mut(),
                published_path_wide.as_ptr(),
                DIIRFLAG_INF_ALREADY_COPIED,
                &mut reboot_required,
            )
        } == 0
        {
            return Err(last_driver_error("driver package could not be installed"));
        }
        Ok(WindowsDriverInstallResult {
            inf_path: published_path,
            reboot_required: reboot_required != 0,
        })
    }

    pub fn uninstall_driver(inf_path: &Path) -> DomainResult<bool> {
        let inf_path = fs::canonicalize(inf_path)
            .map_err(|_| driver_error("driver INF could not be resolved"))?;
        let path = wide_os(inf_path.as_os_str());
        let mut reboot_required = 0;
        if unsafe { DiUninstallDriverW(null_mut(), path.as_ptr(), 0, &mut reboot_required) } == 0 {
            return Err(last_driver_error("driver package could not be uninstalled"));
        }
        Ok(reboot_required != 0)
    }

    fn open_manager(access: u32) -> DomainResult<ServiceHandle> {
        let handle = unsafe { OpenSCManagerW(null(), null(), access) };
        if handle.is_null() {
            return Err(last_service_error(
                "service control manager could not be opened",
            ));
        }
        Ok(ServiceHandle(handle))
    }

    fn open_service(manager: SC_HANDLE, access: u32) -> DomainResult<ServiceHandle> {
        let name = wide(NETWORKCORE_WINDOWS_SERVICE_NAME);
        let handle = unsafe { OpenServiceW(manager, name.as_ptr(), access) };
        if handle.is_null() {
            return Err(last_service_error(
                "NetworkCore service could not be opened",
            ));
        }
        Ok(ServiceHandle(handle))
    }

    fn query_service(service: &ServiceHandle) -> DomainResult<WindowsServiceStatus> {
        let mut status: SERVICE_STATUS_PROCESS = unsafe { zeroed() };
        let mut required = 0;
        let queried = unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                &mut status as *mut _ as *mut u8,
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut required,
            )
        };
        if queried == 0 {
            return Err(last_service_error("service status could not be queried"));
        }
        Ok(WindowsServiceStatus {
            state: map_service_state(status.dwCurrentState),
            process_id: status.dwProcessId,
        })
    }

    fn wait_for_service_state(
        service: &ServiceHandle,
        target: WindowsServiceState,
    ) -> DomainResult<WindowsServiceStatus> {
        let deadline = Instant::now() + SERVICE_WAIT_TIMEOUT;
        loop {
            let status = query_service(service)?;
            if status.state == target {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(service_error("service state transition timed out"));
            }
            thread::sleep(Duration::from_millis(250));
        }
    }

    fn map_service_state(state: u32) -> WindowsServiceState {
        match state {
            SERVICE_STOPPED => WindowsServiceState::Stopped,
            SERVICE_START_PENDING => WindowsServiceState::StartPending,
            SERVICE_RUNNING => WindowsServiceState::Running,
            SERVICE_STOP_PENDING => WindowsServiceState::StopPending,
            SERVICE_PAUSED => WindowsServiceState::Paused,
            _ => WindowsServiceState::Unknown,
        }
    }

    fn open_internet_settings_key() -> DomainResult<RegistryKey> {
        let path = wide(INTERNET_SETTINGS_KEY);
        let mut key: HKEY = null_mut();
        let result = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut key,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(proxy_win32_error(
                "Internet Settings could not be opened",
                result,
            ));
        }
        Ok(RegistryKey(key))
    }

    fn read_registry_dword(key: &RegistryKey, name: &str) -> DomainResult<u32> {
        let name = wide(name);
        let mut value = 0u32;
        let mut size = size_of::<u32>() as u32;
        let mut value_type = 0;
        let result = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null(),
                &mut value_type,
                &mut value as *mut _ as *mut u8,
                &mut size,
            )
        };
        if result == ERROR_FILE_NOT_FOUND {
            return Ok(0);
        }
        if result != ERROR_SUCCESS || value_type != REG_DWORD {
            return Err(proxy_win32_error("proxy DWORD could not be read", result));
        }
        Ok(value)
    }

    fn read_registry_string(key: &RegistryKey, name: &str) -> DomainResult<String> {
        let name = wide(name);
        let mut size = 0u32;
        let mut value_type = 0;
        let first = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null(),
                &mut value_type,
                null_mut(),
                &mut size,
            )
        };
        if first != ERROR_SUCCESS {
            return Ok(String::new());
        }
        if value_type != REG_SZ || size == 0 {
            return Ok(String::new());
        }
        let mut value = vec![0u16; (size as usize).div_ceil(2)];
        let result = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                null(),
                &mut value_type,
                value.as_mut_ptr() as *mut u8,
                &mut size,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(proxy_win32_error("proxy string could not be read", result));
        }
        Ok(String::from_utf16_lossy(
            &value[..value
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(value.len())],
        ))
    }

    fn write_registry_dword(key: &RegistryKey, name: &str, value: u32) -> DomainResult<()> {
        let name = wide(name);
        let result = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_DWORD,
                &value as *const _ as *const u8,
                size_of::<u32>() as u32,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(proxy_win32_error(
                "proxy DWORD could not be written",
                result,
            ));
        }
        Ok(())
    }

    fn write_registry_string(key: &RegistryKey, name: &str, value: &str) -> DomainResult<()> {
        let name = wide(name);
        let value = wide(value);
        let result = unsafe {
            RegSetValueExW(
                key.0,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr() as *const u8,
                (value.len() * size_of::<u16>()) as u32,
            )
        };
        if result != ERROR_SUCCESS {
            return Err(proxy_win32_error(
                "proxy string could not be written",
                result,
            ));
        }
        Ok(())
    }

    fn read_winhttp_snapshot(snapshot: &mut WindowsProxySnapshot) -> DomainResult<()> {
        let mut info = WINHTTP_PROXY_INFO::default();
        if unsafe { WinHttpGetDefaultProxyConfiguration(&mut info) } == 0 {
            return Err(last_proxy_error("WinHTTP proxy could not be read"));
        }
        snapshot.winhttp_access_type = info.dwAccessType;
        snapshot.winhttp_server = unsafe { read_allocated_wide(info.lpszProxy) };
        snapshot.winhttp_bypass = unsafe { read_allocated_wide(info.lpszProxyBypass) };
        unsafe {
            if !info.lpszProxy.is_null() {
                GlobalFree(info.lpszProxy as *mut c_void);
            }
            if !info.lpszProxyBypass.is_null() {
                GlobalFree(info.lpszProxyBypass as *mut c_void);
            }
        }
        Ok(())
    }

    fn set_winhttp_proxy(enabled: bool, server: &str, bypass: &str) -> DomainResult<()> {
        let mut server_wide = wide(server);
        let mut bypass_wide = wide(bypass);
        let mut info = WINHTTP_PROXY_INFO {
            dwAccessType: if enabled {
                WINHTTP_ACCESS_TYPE_NAMED_PROXY
            } else {
                WINHTTP_ACCESS_TYPE_NO_PROXY
            },
            lpszProxy: if enabled {
                server_wide.as_mut_ptr()
            } else {
                null_mut()
            },
            lpszProxyBypass: if enabled && !bypass.is_empty() {
                bypass_wide.as_mut_ptr()
            } else {
                null_mut()
            },
        };
        if unsafe { WinHttpSetDefaultProxyConfiguration(&mut info) } == 0 {
            return Err(last_proxy_error("WinHTTP proxy could not be updated"));
        }
        Ok(())
    }

    fn notify_proxy_change() -> DomainResult<()> {
        for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
            if unsafe { InternetSetOptionW(null(), option, null(), 0) } == 0 {
                return Err(last_proxy_error("WinINet proxy notification failed"));
            }
        }
        Ok(())
    }

    fn open_root_store() -> DomainResult<*mut c_void> {
        let store_name = wide("ROOT");
        let store = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                CERT_SYSTEM_STORE_LOCAL_MACHINE
                    | CERT_STORE_OPEN_EXISTING_FLAG
                    | CERT_STORE_MAXIMUM_ALLOWED_FLAG,
                store_name.as_ptr() as *const c_void,
            )
        };
        if store.is_null() {
            return Err(last_certificate_error(
                "local machine ROOT store could not be opened",
            ));
        }
        Ok(store)
    }

    fn certificate_sha1(context: *const CERT_CONTEXT) -> DomainResult<String> {
        let mut size = 0u32;
        if unsafe {
            CertGetCertificateContextProperty(
                context,
                CERT_SHA1_HASH_PROP_ID,
                null_mut(),
                &mut size,
            )
        } == 0
        {
            return Err(last_certificate_error(
                "certificate thumbprint size could not be read",
            ));
        }
        let mut bytes = vec![0u8; size as usize];
        if unsafe {
            CertGetCertificateContextProperty(
                context,
                CERT_SHA1_HASH_PROP_ID,
                bytes.as_mut_ptr() as *mut c_void,
                &mut size,
            )
        } == 0
        {
            return Err(last_certificate_error(
                "certificate thumbprint could not be read",
            ));
        }
        Ok(bytes.iter().map(|byte| format!("{byte:02X}")).collect())
    }

    fn parse_sha1(value: &str) -> DomainResult<Vec<u8>> {
        let compact: String = value
            .chars()
            .filter(|value| !value.is_whitespace())
            .collect();
        if compact.len() != 40 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(certificate_error(
                "certificate thumbprint must be 40 hexadecimal digits",
            ));
        }
        (0..compact.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&compact[index..index + 2], 16)
                    .map_err(|_| certificate_error("certificate thumbprint is invalid"))
            })
            .collect()
    }

    unsafe fn read_allocated_wide(pointer: *const u16) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let mut length = 0;
        while *pointer.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(pointer, length))
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn wide_os(value: &std::ffi::OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn service_error(message: &str) -> DomainError {
        DomainError::new(WINDOWS_SERVICE_OPERATION_FAILED_CODE, message)
    }

    fn service_win32_error(message: &str, error: u32) -> DomainError {
        DomainError::new(
            WINDOWS_SERVICE_OPERATION_FAILED_CODE,
            format!("{message} (win32={error})"),
        )
    }

    fn last_service_error(message: &str) -> DomainError {
        service_win32_error(message, unsafe { GetLastError() })
    }

    fn proxy_win32_error(message: &str, error: u32) -> DomainError {
        DomainError::new(
            WINDOWS_PROXY_OPERATION_FAILED_CODE,
            format!("{message} (win32={error})"),
        )
    }

    fn last_proxy_error(message: &str) -> DomainError {
        proxy_win32_error(message, unsafe { GetLastError() })
    }

    fn certificate_error(message: &str) -> DomainError {
        DomainError::new(WINDOWS_CERTIFICATE_OPERATION_FAILED_CODE, message)
    }

    fn last_certificate_error(message: &str) -> DomainError {
        DomainError::new(
            WINDOWS_CERTIFICATE_OPERATION_FAILED_CODE,
            format!("{message} (win32={})", unsafe { GetLastError() }),
        )
    }

    fn driver_error(message: &str) -> DomainError {
        DomainError::new(WINDOWS_DRIVER_OPERATION_FAILED_CODE, message)
    }

    fn last_driver_error(message: &str) -> DomainError {
        DomainError::new(
            WINDOWS_DRIVER_OPERATION_FAILED_CODE,
            format!("{message} (win32={})", unsafe { GetLastError() }),
        )
    }
}
