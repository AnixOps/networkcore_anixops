#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("networkcore-windows-gui requires Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    let debug = std::env::args().any(|argument| argument == "--debug" || argument == "-d");
    if let Err(error) = gui::run(debug) {
        gui::show_fatal_error(&error);
    }
}

#[cfg(windows)]
mod gui {
    use config_core::CoreSubscriptionService;
    use control_domain::{NodeDescriptor, SubscriptionService, SubscriptionSource};
    use engine_singbox::{
        inspect_sing_box_native_config, render_sing_box_local_proxy_selector_config,
        rewrite_sing_box_mixed_inbound_listener, select_sing_box_clash_api_outbound,
        sing_box_local_selector_outbound_tag, GithubSingBoxReleaseInstaller, SingBoxInstallRequest,
        SingBoxLocalControllerConfig, SingBoxLocalProxyConfigRequest,
        SingBoxLocalProxySelectableNode, SingBoxManagedProcessRequest,
        SingBoxManagedProcessSupervisor, SingBoxReleaseInstaller, SingBoxTarget, SingBoxTargetArch,
        SingBoxTargetOs,
    };
    use platform_windows::managed::{
        append_managed_log, read_managed_config, read_managed_state, windows_managed_config_path,
        windows_managed_data_directory, windows_managed_log_directory, windows_managed_state_path,
        write_managed_config, write_managed_state, write_managed_text_atomic, WindowsManagedConfig,
        WindowsManagedNativeMitmConfig, WindowsManagedSingBoxConfig, WindowsProxySettings,
        WindowsProxySnapshot, WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
    };
    use platform_windows::system_integration::{
        NativeWindowsSystemIntegration, WindowsServiceState, WindowsSystemIntegration,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use serde::{Deserialize, Serialize};
    use std::env;
    use std::fs;
    use std::mem::zeroed;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{GetLastError, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::Graphics::Gdi::{
        GetStockObject, UpdateWindow, COLOR_WINDOW, DEFAULT_GUI_FONT,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, LoadCursorW, MessageBoxW,
        PostQuitMessage, RegisterClassW, SendMessageW, SetWindowLongPtrW, SetWindowTextW,
        ShowWindow, TranslateMessage, BS_GROUPBOX, CBS_DROPDOWN, CB_ADDSTRING, CB_RESETCONTENT,
        CB_SETCURSEL, CW_USEDEFAULT, ES_AUTOHSCROLL, GWLP_USERDATA, HMENU, IDC_ARROW, MB_ICONERROR,
        MB_OK, MSG, SW_SHOWNORMAL, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_NCDESTROY,
        WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN, WS_OVERLAPPED,
        WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
    };

    const APP_CLASS: &str = "AnixOpsNetworkCoreWindow";
    const APP_TITLE: &str = "AnixOps NetworkCore";
    const DESKTOP_STATE_FILE: &str = "desktop-state.json";

    const ID_REFRESH: usize = 100;
    const ID_INSTALL_SERVICE: usize = 101;
    const ID_START_SERVICE: usize = 102;
    const ID_STOP_SERVICE: usize = 103;
    const ID_RESTART_SERVICE: usize = 104;
    const ID_APPLY_CONFIG: usize = 110;
    const ID_OPEN_MANAGED_CONFIG: usize = 111;
    const ID_VALIDATE_CONFIGURATION: usize = 112;
    const ID_SWITCH_PROFILE_NODE: usize = 113;
    const ID_LOAD_PROFILE_NODES: usize = 114;
    const ID_INSTALL_SING_BOX: usize = 115;
    const ID_IMPORT_PROFILE: usize = 116;
    const ID_ENABLE_HTTPS_MITM: usize = 117;
    const ID_DISABLE_HTTPS_MITM: usize = 118;
    const ID_UPDATE_PROFILE: usize = 119;
    const ID_ENABLE_PROXY: usize = 120;
    const ID_RESTORE_PROXY: usize = 121;
    const ID_INSTALL_CERTIFICATE: usize = 130;
    const ID_REMOVE_CERTIFICATE: usize = 131;
    const ID_INSTALL_DRIVER: usize = 140;
    const ID_REMOVE_DRIVER: usize = 141;
    const ID_TOGGLE_DEBUG: usize = 150;
    const ID_OPEN_LOGS: usize = 151;
    const ID_OPEN_CORE_LOG: usize = 152;
    const ID_SHOW_DIAGNOSTICS: usize = 153;

    const SING_BOX_DIRECT_LISTEN_PORT: u16 = 7890;
    const SING_BOX_MITM_UPSTREAM_PORT: u16 = 7891;
    const NATIVE_MITM_LISTEN_PORT: u16 = 7890;
    const MITM_CA_SUBJECT: &str = "AnixOps NetworkCore Windows HTTPS MITM CA";

    #[derive(Debug, Default, Serialize, Deserialize)]
    struct DesktopState {
        proxy_snapshot: Option<WindowsProxySnapshot>,
        certificate_sha1: Option<String>,
        driver_inf_path: Option<PathBuf>,
        #[serde(default)]
        sing_box_executable_path: Option<PathBuf>,
        #[serde(default)]
        profile_source_path: Option<PathBuf>,
        #[serde(default)]
        profile_source_url: Option<String>,
        #[serde(default)]
        profile_node_id: Option<String>,
        #[serde(default)]
        debug_enabled: bool,
    }

    struct AppState {
        integration: NativeWindowsSystemIntegration,
        service_status: HWND,
        activity: HWND,
        debug_status: HWND,
        config_path: HWND,
        profile_source: HWND,
        profile_node_id: HWND,
        proxy_server: HWND,
        proxy_bypass: HWND,
        certificate_path: HWND,
        driver_path: HWND,
        desktop: DesktopState,
        profile_nodes: Vec<ProfileNodeOption>,
    }

    struct ImportedSingBoxProfile {
        executable_path: PathBuf,
        config_path: PathBuf,
        config_parent: PathBuf,
        local_http_proxy: Option<String>,
        sing_box_config_snapshot_path: Option<PathBuf>,
    }

    struct ProfilePayload {
        payload: String,
        source_path: Option<PathBuf>,
        source_url: Option<String>,
    }

    struct ProfileNodeOption {
        id: String,
        label: String,
        selector_outbound_tag: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProfileRenderMode {
        Direct,
        NativeMitm,
    }

    pub fn run(debug: bool) -> Result<(), String> {
        let _ = append_managed_log("gui", &format!("startup debug={debug}"));
        if unsafe { IsUserAnAdmin() } == 0 {
            elevate(debug)?;
            return Ok(());
        }

        let instance = unsafe { GetModuleHandleW(null()) };
        if instance.is_null() {
            return Err(last_error("Windows module handle could not be acquired"));
        }

        let class_name = wide(APP_CLASS);
        let window_class = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: null_mut(),
            hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
            hbrBackground: (COLOR_WINDOW + 1) as _,
            lpszMenuName: null(),
            lpszClassName: class_name.as_ptr(),
        };
        if unsafe { RegisterClassW(&window_class) } == 0 {
            return Err(last_error(
                "NetworkCore window class could not be registered",
            ));
        }

        let title = wide(APP_TITLE);
        let window = unsafe {
            CreateWindowExW(
                0,
                class_name.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                980,
                980,
                null_mut(),
                null_mut(),
                instance,
                null(),
            )
        };
        if window.is_null() {
            return Err(last_error("NetworkCore window could not be created"));
        }

        unsafe {
            ShowWindow(window, SW_SHOWNORMAL);
            UpdateWindow(window);
        }

        let mut message: MSG = unsafe { zeroed() };
        loop {
            let result = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
            if result == -1 {
                return Err(last_error("Windows message loop failed"));
            }
            if result == 0 {
                break;
            }
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        Ok(())
    }

    pub fn show_fatal_error(message: &str) {
        let _ = append_managed_log("gui", &format!("fatal: {message}"));
        let title = wide(APP_TITLE);
        let message = wide(message);
        unsafe {
            MessageBoxW(
                null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    unsafe extern "system" fn window_proc(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match message {
            WM_CREATE => match create_interface(window) {
                Ok(state) => {
                    SetWindowLongPtrW(window, GWLP_USERDATA, Box::into_raw(state) as isize);
                    with_state(window, |state| refresh(state));
                    0
                }
                Err(error) => {
                    show_fatal_error(&error);
                    -1
                }
            },
            WM_COMMAND => {
                let id = wparam & 0xffff;
                with_state(window, |state| handle_command(state, id));
                0
            }
            WM_CLOSE => {
                DestroyWindow(window);
                0
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                0
            }
            WM_NCDESTROY => {
                let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut AppState;
                if !pointer.is_null() {
                    SetWindowLongPtrW(window, GWLP_USERDATA, 0);
                    drop(Box::from_raw(pointer));
                }
                DefWindowProcW(window, message, wparam, lparam)
            }
            _ => DefWindowProcW(window, message, wparam, lparam),
        }
    }

    unsafe fn with_state(window: HWND, action: impl FnOnce(&mut AppState)) {
        let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut AppState;
        if !pointer.is_null() {
            action(&mut *pointer);
        }
    }

    unsafe fn create_interface(window: HWND) -> Result<Box<AppState>, String> {
        let instance = GetModuleHandleW(null());
        let font = GetStockObject(DEFAULT_GUI_FONT);
        let mut desktop = load_desktop_state();
        if std::env::args().any(|argument| argument == "--debug" || argument == "-d") {
            desktop.debug_enabled = true;
        }

        create_label(window, instance, font, "NetworkCore", 24, 16, 600, 32);
        create_label(
            window,
            instance,
            font,
            "Managed Windows networking",
            24,
            48,
            600,
            22,
        );

        create_group(window, instance, font, "Managed service", 20, 82, 925, 118);
        let service_status = create_label(
            window,
            instance,
            font,
            "Service status: loading",
            40,
            108,
            860,
            24,
        );
        create_button(
            window, instance, font, "Refresh", ID_REFRESH, 40, 150, 110, 30,
        );
        create_button(
            window,
            instance,
            font,
            "Install service",
            ID_INSTALL_SERVICE,
            160,
            150,
            135,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Start",
            ID_START_SERVICE,
            305,
            150,
            100,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Stop",
            ID_STOP_SERVICE,
            415,
            150,
            100,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Restart",
            ID_RESTART_SERVICE,
            525,
            150,
            100,
            30,
        );

        create_group(
            window,
            instance,
            font,
            "Managed configuration",
            20,
            210,
            925,
            100,
        );
        create_label(window, instance, font, "JSON file", 40, 242, 100, 22);
        let config_path = create_edit(
            window,
            instance,
            font,
            windows_managed_config_path().to_string_lossy().as_ref(),
            140,
            238,
            440,
            28,
        );
        create_button(
            window,
            instance,
            font,
            "Open JSON",
            ID_OPEN_MANAGED_CONFIG,
            590,
            237,
            95,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Validate",
            ID_VALIDATE_CONFIGURATION,
            695,
            237,
            95,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Apply configuration",
            ID_APPLY_CONFIG,
            800,
            237,
            125,
            30,
        );

        create_group(
            window,
            instance,
            font,
            "sing-box profile",
            20,
            320,
            925,
            170,
        );
        let profile_source_text = desktop
            .profile_source_url
            .clone()
            .or_else(|| {
                desktop
                    .profile_source_path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned())
            })
            .unwrap_or_default();
        create_label(window, instance, font, "Profile / URL", 40, 352, 100, 22);
        let profile_source = create_edit(
            window,
            instance,
            font,
            &profile_source_text,
            140,
            348,
            500,
            28,
        );
        create_button(
            window,
            instance,
            font,
            "Install core",
            ID_INSTALL_SING_BOX,
            655,
            347,
            120,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Import profile",
            ID_IMPORT_PROFILE,
            785,
            347,
            140,
            30,
        );
        create_label(window, instance, font, "Node ID", 40, 398, 100, 22);
        let profile_node_id = create_profile_node_selector(
            window,
            instance,
            font,
            desktop.profile_node_id.as_deref().unwrap_or(""),
            140,
            394,
            350,
            28,
        );
        create_button(
            window,
            instance,
            font,
            "Load nodes",
            ID_LOAD_PROFILE_NODES,
            500,
            393,
            130,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Update URL",
            ID_UPDATE_PROFILE,
            640,
            393,
            120,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Switch active",
            ID_SWITCH_PROFILE_NODE,
            770,
            393,
            155,
            30,
        );
        create_label(window, instance, font, "HTTPS MITM", 40, 442, 100, 22);
        create_button(
            window,
            instance,
            font,
            "Enable HTTPS MITM",
            ID_ENABLE_HTTPS_MITM,
            140,
            438,
            175,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Disable HTTPS MITM",
            ID_DISABLE_HTTPS_MITM,
            325,
            438,
            175,
            30,
        );

        create_group(window, instance, font, "System proxy", 20, 500, 925, 130);
        create_label(window, instance, font, "Server", 40, 530, 90, 22);
        let proxy_server = create_edit(window, instance, font, "127.0.0.1:7890", 130, 526, 300, 28);
        create_label(window, instance, font, "Bypass", 450, 530, 90, 22);
        let proxy_bypass = create_edit(window, instance, font, "<local>", 540, 526, 365, 28);
        create_button(
            window,
            instance,
            font,
            "Enable proxy",
            ID_ENABLE_PROXY,
            40,
            574,
            130,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Restore proxy",
            ID_RESTORE_PROXY,
            180,
            574,
            130,
            30,
        );

        create_group(
            window,
            instance,
            font,
            "Trust and driver",
            20,
            640,
            925,
            142,
        );
        create_label(window, instance, font, "Root CA", 40, 672, 90, 22);
        let certificate_path = create_edit(window, instance, font, "", 130, 668, 575, 28);
        create_button(
            window,
            instance,
            font,
            "Install CA",
            ID_INSTALL_CERTIFICATE,
            720,
            667,
            95,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Remove CA",
            ID_REMOVE_CERTIFICATE,
            825,
            667,
            100,
            30,
        );
        create_label(window, instance, font, "Driver INF", 40, 722, 90, 22);
        let driver_path = create_edit(window, instance, font, "", 130, 718, 575, 28);
        create_button(
            window,
            instance,
            font,
            "Install driver",
            ID_INSTALL_DRIVER,
            720,
            717,
            95,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Remove driver",
            ID_REMOVE_DRIVER,
            825,
            717,
            100,
            30,
        );

        let activity = create_label(window, instance, font, "Ready", 24, 800, 910, 26);
        let debug_status = create_label(
            window,
            instance,
            font,
            &format!(
                "Debug logging: {}",
                if desktop.debug_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            ),
            24,
            832,
            360,
            24,
        );
        create_button(
            window,
            instance,
            font,
            "Toggle debug",
            ID_TOGGLE_DEBUG,
            390,
            828,
            120,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Open log folder",
            ID_OPEN_LOGS,
            520,
            828,
            130,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Open core log",
            ID_OPEN_CORE_LOG,
            660,
            828,
            120,
            30,
        );
        create_button(
            window,
            instance,
            font,
            "Diagnostics",
            ID_SHOW_DIAGNOSTICS,
            790,
            828,
            135,
            30,
        );
        create_label(
            window,
            instance,
            font,
            &format!("Logs: {}", windows_managed_log_directory().display()),
            24,
            868,
            900,
            24,
        );

        let mut state = Box::new(AppState {
            integration: NativeWindowsSystemIntegration::new(),
            service_status,
            activity,
            debug_status,
            config_path,
            profile_source,
            profile_node_id,
            proxy_server,
            proxy_bypass,
            certificate_path,
            driver_path,
            desktop,
            profile_nodes: Vec::new(),
        });
        let _ = save_desktop_state(&state.desktop);
        load_configuration_fields(&mut state);
        update_debug_status(&mut state);
        Ok(state)
    }

    unsafe fn handle_command(state: &mut AppState, id: usize) {
        match id {
            ID_REFRESH => refresh(state),
            ID_INSTALL_SERVICE => run_action(state, "Service installed", install_service),
            ID_START_SERVICE => run_action(state, "Service started", start_service),
            ID_STOP_SERVICE => run_action(state, "Service stopped", stop_service),
            ID_RESTART_SERVICE => run_action(state, "Service restarted", restart_service),
            ID_APPLY_CONFIG => run_action(state, "Configuration applied", apply_configuration),
            ID_OPEN_MANAGED_CONFIG => {
                run_action(state, "Configuration opened", open_managed_config)
            }
            ID_VALIDATE_CONFIGURATION => {
                run_action(state, "Configuration validated", validate_configuration)
            }
            ID_INSTALL_SING_BOX => run_action(state, "sing-box core installed", install_sing_box),
            ID_LOAD_PROFILE_NODES => {
                run_action(state, "Subscription nodes loaded", load_profile_nodes)
            }
            ID_IMPORT_PROFILE => run_action(state, "sing-box profile imported", import_profile),
            ID_SWITCH_PROFILE_NODE => {
                run_action(state, "Active sing-box node switched", switch_profile_node)
            }
            ID_UPDATE_PROFILE => run_action(state, "Subscription URL updated", update_profile),
            ID_ENABLE_HTTPS_MITM => run_action(state, "HTTPS MITM configured", enable_https_mitm),
            ID_DISABLE_HTTPS_MITM => run_action(state, "HTTPS MITM disabled", disable_https_mitm),
            ID_ENABLE_PROXY => run_action(state, "System proxy enabled", enable_proxy),
            ID_RESTORE_PROXY => run_action(state, "System proxy restored", restore_proxy),
            ID_INSTALL_CERTIFICATE => {
                run_action(state, "Root certificate installed", install_certificate)
            }
            ID_REMOVE_CERTIFICATE => {
                run_action(state, "Root certificate removed", remove_certificate)
            }
            ID_INSTALL_DRIVER => run_action(state, "Driver installed", install_driver),
            ID_REMOVE_DRIVER => run_action(state, "Driver removed", remove_driver),
            ID_TOGGLE_DEBUG => toggle_debug(state),
            ID_OPEN_LOGS => run_action(state, "Log folder opened", open_log_directory),
            ID_OPEN_CORE_LOG => run_action(state, "sing-box log opened", open_sing_box_log),
            ID_SHOW_DIAGNOSTICS => run_action(state, "Diagnostics opened", show_diagnostics),
            _ => {}
        }
    }

    unsafe fn run_action(
        state: &mut AppState,
        success: &str,
        action: fn(&mut AppState) -> Result<(), String>,
    ) {
        match action(state) {
            Ok(()) => {
                if state.desktop.debug_enabled {
                    let _ = append_managed_log("gui", &format!("debug: success: {success}"));
                }
                set_text(state.activity, success);
                refresh(state);
            }
            Err(error) => {
                let _ = append_managed_log("gui", &format!("error: {error}"));
                let report = write_diagnostic_report(state).ok();
                let message = match report {
                    Some(path) => format!("{error}\n\nDiagnostics: {}", path.display()),
                    None => error,
                };
                set_text(state.activity, &message);
                refresh(state);
                let title = wide(APP_TITLE);
                let message = wide(&message);
                MessageBoxW(
                    null_mut(),
                    message.as_ptr(),
                    title.as_ptr(),
                    MB_OK | MB_ICONERROR,
                );
            }
        }
    }

    unsafe fn refresh(state: &mut AppState) {
        match state.integration.service_status() {
            Ok(status) => {
                let label = match status.state {
                    WindowsServiceState::NotInstalled => "Not installed".to_string(),
                    WindowsServiceState::Stopped => "Stopped".to_string(),
                    WindowsServiceState::StartPending => "Starting".to_string(),
                    WindowsServiceState::Running => format!("Running (PID {})", status.process_id),
                    WindowsServiceState::StopPending => "Stopping".to_string(),
                    WindowsServiceState::Paused => "Paused".to_string(),
                    WindowsServiceState::Unknown => "Unknown".to_string(),
                };
                let core = match read_managed_state(&windows_managed_state_path()) {
                    Ok(managed) => {
                        let sing_box = if managed.sing_box_running {
                            format!(
                                "sing-box running (PID {})",
                                managed
                                    .sing_box_process_id
                                    .map(|pid| pid.to_string())
                                    .unwrap_or_else(|| "unknown".to_string())
                            )
                        } else {
                            format!(
                                "sing-box stopped{}",
                                managed
                                    .sing_box_exit_code
                                    .map(|code| format!(" (exit {code})"))
                                    .unwrap_or_default()
                            )
                        };
                        if managed.native_mitm_running {
                            format!(
                                "{sing_box}; HTTPS MITM listening {}",
                                managed
                                    .native_mitm_listener
                                    .unwrap_or_else(|| "unknown".to_string())
                            )
                        } else if let Some(error) = managed.native_mitm_last_error {
                            format!("{sing_box}; HTTPS MITM failed: {error}")
                        } else {
                            format!("{sing_box}; HTTPS MITM stopped")
                        }
                    }
                    Err(error) => format!("managed runtime state unavailable: {error}"),
                };
                set_text(
                    state.service_status,
                    &format!("Service status: {label}; {core}"),
                );
                if state.desktop.debug_enabled {
                    let _ = append_managed_log(
                        "gui",
                        &format!("debug: service status: {label}; {core}"),
                    );
                }
            }
            Err(error) => {
                let message = format!("Service status: {error}");
                let _ = append_managed_log("gui", &message);
                set_text(state.service_status, &message);
            }
        }
    }

    unsafe fn toggle_debug(state: &mut AppState) {
        state.desktop.debug_enabled = !state.desktop.debug_enabled;
        let message = if state.desktop.debug_enabled {
            "Debug logging enabled"
        } else {
            "Debug logging disabled"
        };
        let _ = append_managed_log("gui", message);
        if let Err(error) = save_desktop_state(&state.desktop) {
            set_text(state.activity, &error);
            let _ = append_managed_log("gui", &format!("error: {error}"));
            return;
        }
        set_text(state.activity, message);
        update_debug_status(state);
    }

    fn open_log_directory(_state: &mut AppState) -> Result<(), String> {
        open_path(&windows_managed_log_directory(), "log directory")
    }

    fn open_sing_box_log(_state: &mut AppState) -> Result<(), String> {
        let path = read_managed_config(&windows_managed_config_path())
            .ok()
            .and_then(|config| config.sing_box.map(|config| config.log_path))
            .unwrap_or_else(|| windows_managed_log_directory().join("sing-box.log"));
        if !path.exists() {
            return Err(format!(
                "sing-box log is not available yet: {}",
                path.display()
            ));
        }
        open_path(&path, "sing-box log")
    }

    fn open_managed_config(state: &mut AppState) -> Result<(), String> {
        let path = PathBuf::from(unsafe { get_text(state.config_path) });
        if path.as_os_str().is_empty() {
            return Err("Managed configuration path is required".to_string());
        }
        if !path.exists() {
            return Err(format!(
                "Managed configuration is not available yet: {}",
                path.display()
            ));
        }
        open_path(&path, "managed configuration")
    }

    fn validate_configuration(state: &mut AppState) -> Result<(), String> {
        let path = PathBuf::from(unsafe { get_text(state.config_path) });
        let config = read_managed_config(&path).map_err(|error| error.to_string())?;
        if let Some(sing_box) = config.sing_box.filter(|sing_box| sing_box.enabled) {
            let log_path = sing_box.log_path.clone();
            SingBoxManagedProcessSupervisor::check_configuration(&SingBoxManagedProcessRequest {
                executable_path: sing_box.executable_path,
                config_path: sing_box.config_path,
                working_directory: sing_box.working_directory,
                log_path: log_path.clone(),
            })
            .map_err(|error| {
                format!(
                    "{error}; inspect the sing-box check output in {}",
                    log_path.display()
                )
            })?;
        }
        let report = write_diagnostic_report(state)?;
        let _ = append_managed_log(
            "gui",
            &format!(
                "configuration preflight succeeded report={}",
                report.display()
            ),
        );
        Ok(())
    }

    fn show_diagnostics(state: &mut AppState) -> Result<(), String> {
        let path = write_diagnostic_report(state)?;
        open_path(&path, "diagnostic report")
    }

    fn write_diagnostic_report(state: &mut AppState) -> Result<PathBuf, String> {
        let config_path = PathBuf::from(unsafe { get_text(state.config_path) });
        let mut report = String::from("AnixOps NetworkCore Windows diagnostics\n");
        report.push_str(&format!("managed_config_path={}\n", config_path.display()));

        match state.integration.service_status() {
            Ok(status) => report.push_str(&format!(
                "service_state={:?} service_process_id={}\n",
                status.state, status.process_id
            )),
            Err(error) => report.push_str(&format!("service_status_error={error}\n")),
        }

        let config = match read_managed_config(&config_path) {
            Ok(config) => {
                report.push_str(&format!(
                    "managed_config_schema_version={} sing_box_enabled={} native_mitm_enabled={}\n",
                    config.schema_version,
                    config
                        .sing_box
                        .as_ref()
                        .is_some_and(|sing_box| sing_box.enabled),
                    config
                        .native_mitm
                        .as_ref()
                        .is_some_and(|native_mitm| native_mitm.enabled)
                ));
                Some(config)
            }
            Err(error) => {
                report.push_str(&format!("managed_config_error={error}\n"));
                None
            }
        };

        match read_managed_state(&windows_managed_state_path()) {
            Ok(managed) => report.push_str(&format!(
                "runtime_transition={} sing_box_running={} sing_box_pid={} sing_box_exit_code={} native_mitm_running={} native_mitm_listener={} native_mitm_error={}\n",
                managed.last_transition,
                managed.sing_box_running,
                managed
                    .sing_box_process_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                managed
                    .sing_box_exit_code
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                managed.native_mitm_running,
                managed.native_mitm_listener.unwrap_or_else(|| "none".to_string()),
                managed.native_mitm_last_error.unwrap_or_else(|| "none".to_string())
            )),
            Err(error) => report.push_str(&format!("managed_state_error={error}\n")),
        }

        let mut logs = vec![
            windows_managed_log_directory().join("gui.log"),
            windows_managed_log_directory().join("service.log"),
        ];
        if let Some(config) = config {
            if let Some(sing_box) = config.sing_box {
                logs.push(sing_box.log_path);
            }
            if let Some(native_mitm) = config.native_mitm {
                logs.push(native_mitm.log_path);
            }
        }
        logs.sort();
        logs.dedup();
        for path in logs {
            report.push_str(&format!("\n--- log: {} ---\n", path.display()));
            match read_log_tail(&path, 80) {
                Ok(content) if content.is_empty() => report.push_str("(empty)\n"),
                Ok(content) => report.push_str(&content),
                Err(error) => report.push_str(&format!("(unavailable: {error})\n")),
            }
        }

        let path = windows_managed_log_directory().join("diagnostics.txt");
        write_managed_text_atomic(&path, &report).map_err(|error| error.to_string())?;
        Ok(path)
    }

    fn read_log_tail(path: &Path, line_limit: usize) -> Result<String, String> {
        let content = fs::read_to_string(path).map_err(|error| error.to_string())?;
        let lines = content.lines().collect::<Vec<_>>();
        let start = lines.len().saturating_sub(line_limit);
        if start == lines.len() {
            return Ok(String::new());
        }
        Ok(format!("{}\n", lines[start..].join("\n")))
    }

    fn open_path(path: &Path, description: &str) -> Result<(), String> {
        let verb = wide("open");
        let path = wide_os(path);
        let result = unsafe {
            ShellExecuteW(
                null_mut(),
                verb.as_ptr(),
                path.as_ptr(),
                null(),
                null(),
                SW_SHOWNORMAL,
            )
        } as isize;
        if result <= 32 {
            return Err(last_error(&format!("{description} could not be opened")));
        }
        Ok(())
    }

    unsafe fn update_debug_status(state: &mut AppState) {
        let status = if state.desktop.debug_enabled {
            "Debug logging: enabled"
        } else {
            "Debug logging: disabled"
        };
        set_text(state.debug_status, status);
    }

    fn install_service(state: &mut AppState) -> Result<(), String> {
        let executable = env::current_exe().map_err(|error| error.to_string())?;
        let service = executable
            .parent()
            .ok_or_else(|| "GUI executable has no parent directory".to_string())?
            .join("networkcore-windows-service.exe");
        state
            .integration
            .install_service(&service)
            .map_err(|error| error.to_string())
    }

    fn start_service(state: &mut AppState) -> Result<(), String> {
        apply_user_proxy_from_config(state)?;
        if let Err(error) = state.integration.start_service() {
            let _ = restore_proxy(state);
            return Err(error.to_string());
        }
        Ok(())
    }

    fn stop_service(state: &mut AppState) -> Result<(), String> {
        state
            .integration
            .stop_service()
            .map_err(|error| error.to_string())?;
        restore_proxy(state)
    }

    fn restart_service(state: &mut AppState) -> Result<(), String> {
        state
            .integration
            .stop_service()
            .map_err(|error| error.to_string())?;
        restore_proxy(state)?;
        apply_user_proxy_from_config(state)?;
        state
            .integration
            .start_service()
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn apply_configuration(state: &mut AppState) -> Result<(), String> {
        let source = PathBuf::from(unsafe { get_text(state.config_path) });
        let config = read_managed_config(&source).map_err(|error| error.to_string())?;
        write_managed_config(&windows_managed_config_path(), &config)
            .map_err(|error| error.to_string())?;
        load_configuration_fields(state);
        Ok(())
    }

    fn install_sing_box(state: &mut AppState) -> Result<(), String> {
        let installer = GithubSingBoxReleaseInstaller::new().map_err(|error| error.to_string())?;
        let report = installer
            .install_latest(&SingBoxInstallRequest {
                install_root: windows_managed_data_directory()
                    .join("sing-box")
                    .join("engine"),
                target: SingBoxTarget::new(SingBoxTargetOs::Windows, SingBoxTargetArch::Amd64),
                force: false,
            })
            .map_err(|error| error.to_string())?;
        state.desktop.sing_box_executable_path = Some(report.executable_path);
        save_desktop_state(&state.desktop)
    }

    fn import_profile(state: &mut AppState) -> Result<(), String> {
        let mut managed = managed_config_or_default()?;
        let native_mitm_enabled = managed
            .native_mitm
            .as_ref()
            .is_some_and(|native_mitm| native_mitm.enabled);
        let (listen_port, mode) = if native_mitm_enabled {
            (SING_BOX_MITM_UPSTREAM_PORT, ProfileRenderMode::NativeMitm)
        } else {
            (SING_BOX_DIRECT_LISTEN_PORT, ProfileRenderMode::Direct)
        };
        let imported = render_local_profile_config(state, listen_port, mode)?;
        managed.system_proxy = if native_mitm_enabled {
            Some(WindowsProxySettings {
                enabled: true,
                server: format!("127.0.0.1:{NATIVE_MITM_LISTEN_PORT}"),
                bypass: "<local>".to_string(),
            })
        } else {
            imported
                .local_http_proxy
                .map(|server| WindowsProxySettings {
                    enabled: true,
                    server,
                    bypass: "<local>".to_string(),
                })
        };
        if native_mitm_enabled {
            if let Some(native_mitm) = managed.native_mitm.as_mut() {
                native_mitm.sing_box_config_snapshot_path =
                    imported.sing_box_config_snapshot_path.clone();
            }
        }
        managed.sing_box = Some(WindowsManagedSingBoxConfig {
            enabled: true,
            executable_path: imported.executable_path,
            config_path: imported.config_path,
            working_directory: Some(imported.config_parent),
            log_path: windows_managed_log_directory().join("sing-box.log"),
        });
        write_managed_config(&windows_managed_config_path(), &managed)
            .map_err(|error| error.to_string())?;
        load_configuration_fields(state);
        Ok(())
    }

    fn update_profile(state: &mut AppState) -> Result<(), String> {
        let location = state
            .desktop
            .profile_source_url
            .clone()
            .filter(|location| !location.trim().is_empty())
            .ok_or_else(|| {
                "Import an HTTP or HTTPS subscription URL before updating it".to_string()
            })?;
        unsafe {
            set_text(state.profile_source, &location);
        }
        import_profile(state)
    }

    fn enable_https_mitm(state: &mut AppState) -> Result<(), String> {
        let imported = render_local_profile_config(
            state,
            SING_BOX_MITM_UPSTREAM_PORT,
            ProfileRenderMode::NativeMitm,
        )?;
        let restart = stop_running_service_for_reconfigure(state)?;
        let (certificate_path, private_key_path) = ensure_mitm_ca_material()?;
        let mut managed = managed_config_or_default()?;
        managed.system_proxy = Some(WindowsProxySettings {
            enabled: true,
            server: format!("127.0.0.1:{NATIVE_MITM_LISTEN_PORT}"),
            bypass: "<local>".to_string(),
        });
        managed.sing_box = Some(WindowsManagedSingBoxConfig {
            enabled: true,
            executable_path: imported.executable_path,
            config_path: imported.config_path,
            working_directory: Some(imported.config_parent),
            log_path: windows_managed_log_directory().join("sing-box.log"),
        });
        managed.native_mitm = Some(WindowsManagedNativeMitmConfig {
            enabled: true,
            listen_host: "127.0.0.1".to_string(),
            listen_port: NATIVE_MITM_LISTEN_PORT,
            upstream_socks_host: "127.0.0.1".to_string(),
            upstream_socks_port: SING_BOX_MITM_UPSTREAM_PORT,
            ca_certificate_path: certificate_path.clone(),
            ca_private_key_path: private_key_path,
            log_path: windows_managed_log_directory().join("native-mitm.log"),
            sing_box_config_snapshot_path: imported.sing_box_config_snapshot_path,
        });
        write_managed_config(&windows_managed_config_path(), &managed)
            .map_err(|error| error.to_string())?;
        unsafe {
            set_text(
                state.certificate_path,
                certificate_path.to_string_lossy().as_ref(),
            );
            set_text(
                state.proxy_server,
                format!("127.0.0.1:{NATIVE_MITM_LISTEN_PORT}").as_str(),
            );
        }
        if restart {
            start_service(state)?;
        }
        Ok(())
    }

    fn disable_https_mitm(state: &mut AppState) -> Result<(), String> {
        let mut managed = managed_config_or_default()?;
        let native_mitm = managed
            .native_mitm
            .take()
            .ok_or_else(|| "HTTPS MITM is not configured".to_string())?;
        let sing_box = managed.sing_box.as_mut().ok_or_else(|| {
            "Managed sing-box configuration is required to disable HTTPS MITM".to_string()
        })?;
        let native_snapshot = native_mitm
            .sing_box_config_snapshot_path
            .as_ref()
            .map(|path| {
                let content = fs::read_to_string(path).map_err(|error| {
                    format!("Native sing-box MITM rollback snapshot could not be read: {error}")
                })?;
                let local_http_proxy = inspect_sing_box_native_config(&content)
                    .and_then(|config| config.local_http_proxy)
                    .map(|proxy| proxy.endpoint());
                Ok::<_, String>((path.clone(), content, local_http_proxy))
            })
            .transpose()?;
        let restart = stop_running_service_for_reconfigure(state)?;
        let direct_proxy_server = if let Some((_, content, local_http_proxy)) = &native_snapshot {
            write_managed_text_atomic(&sing_box.config_path, content).map_err(|error| {
                format!(
                    "Native sing-box configuration could not be restored after HTTPS MITM: {error}"
                )
            })?;
            local_http_proxy.clone()
        } else {
            rewrite_managed_sing_box_listen_port(sing_box, SING_BOX_DIRECT_LISTEN_PORT)?;
            Some(format!("127.0.0.1:{SING_BOX_DIRECT_LISTEN_PORT}"))
        };
        managed.system_proxy = direct_proxy_server.map(|server| WindowsProxySettings {
            enabled: true,
            server,
            bypass: "<local>".to_string(),
        });
        write_managed_config(&windows_managed_config_path(), &managed)
            .map_err(|error| error.to_string())?;
        if let Some((path, _, _)) = native_snapshot {
            if let Err(error) = fs::remove_file(&path) {
                let _ = append_managed_log(
                    "gui",
                    &format!(
                        "native sing-box MITM rollback snapshot retained at {}: {error}",
                        path.display()
                    ),
                );
            }
        }

        if let Ok(mut runtime_state) = read_managed_state(&windows_managed_state_path()) {
            if let Some(thumbprint) = runtime_state.native_mitm_certificate_sha1.take() {
                state
                    .integration
                    .remove_root_certificate(&thumbprint)
                    .map_err(|error| error.to_string())?;
                write_managed_state(&windows_managed_state_path(), &runtime_state)
                    .map_err(|error| error.to_string())?;
            }
        }
        let _ = fs::remove_file(native_mitm.ca_private_key_path);
        if restart {
            start_service(state)?;
        }
        load_configuration_fields(state);
        Ok(())
    }

    fn render_local_profile_config(
        state: &mut AppState,
        listen_port: u16,
        mode: ProfileRenderMode,
    ) -> Result<ImportedSingBoxProfile, String> {
        let executable_path = state
            .desktop
            .sing_box_executable_path
            .clone()
            .filter(|path| path.exists())
            .ok_or_else(|| "Install sing-box before importing a profile".to_string())?;
        let location = unsafe { get_text(state.profile_source) };
        let location = location.trim();
        if location.is_empty() {
            return Err("Profile file path or subscription URL is required".to_string());
        }
        let ProfilePayload {
            payload,
            source_path,
            source_url,
        } = load_profile_payload(location)?;
        let config_path = windows_managed_data_directory()
            .join("sing-box")
            .join("config.json");
        let config_parent = config_path
            .parent()
            .ok_or_else(|| "sing-box config path has no parent directory".to_string())?
            .to_path_buf();
        fs::create_dir_all(&config_parent).map_err(|error| error.to_string())?;

        if let Some(native_config) = inspect_sing_box_native_config(&payload) {
            unsafe {
                clear_profile_node_options(state);
            }
            let local_http_proxy = native_config.local_http_proxy.map(|proxy| proxy.endpoint());
            let sing_box_config_snapshot_path = match mode {
                ProfileRenderMode::Direct => {
                    write_managed_text_atomic(&config_path, &native_config.json)
                        .map_err(|error| error.to_string())?;
                    None
                }
                ProfileRenderMode::NativeMitm => Some(stage_native_sing_box_mitm_config(
                    &config_path,
                    &native_config.json,
                    listen_port,
                )?),
            };
            state.desktop.profile_source_path = source_path;
            state.desktop.profile_source_url = source_url;
            state.desktop.profile_node_id = None;
            save_desktop_state(&state.desktop)?;
            return Ok(ImportedSingBoxProfile {
                executable_path,
                config_path,
                config_parent,
                local_http_proxy,
                sing_box_config_snapshot_path,
            });
        }

        let nodes = parse_profile_nodes(&payload)?;
        unsafe {
            replace_profile_node_options(state, &nodes);
        }
        let selected_node_id = unsafe { selected_profile_node_id(state) };
        let rendered = render_sing_box_local_proxy_selector_config(
            &SingBoxLocalProxyConfigRequest {
                nodes,
                selected_node_id: (!selected_node_id.trim().is_empty())
                    .then_some(selected_node_id.clone()),
                listen_host: "127.0.0.1".to_string(),
                listen_port,
            },
            &SingBoxLocalControllerConfig::loopback_selector(),
        )
        .map_err(|error| error.to_string())?;
        write_managed_text_atomic(&config_path, &rendered.json)
            .map_err(|error| error.to_string())?;

        unsafe {
            replace_profile_node_options_from_selector(state, &rendered.selectable_nodes);
        }
        state.desktop.profile_source_path = source_path;
        state.desktop.profile_source_url = source_url;
        state.desktop.profile_node_id = Some(rendered.selected_node_id);
        save_desktop_state(&state.desktop)?;
        Ok(ImportedSingBoxProfile {
            executable_path,
            config_path,
            config_parent,
            local_http_proxy: Some(format!("127.0.0.1:{listen_port}")),
            sing_box_config_snapshot_path: None,
        })
    }

    fn load_profile_nodes(state: &mut AppState) -> Result<(), String> {
        let location = unsafe { get_text(state.profile_source) };
        let location = location.trim();
        if location.is_empty() {
            return Err("Profile file path or subscription URL is required".to_string());
        }
        let profile = load_profile_payload(location)?;
        if inspect_sing_box_native_config(&profile.payload).is_some() {
            return Err(
                "Native sing-box JSON is passed through unchanged and has no generated node selector"
                    .to_string(),
            );
        }
        let nodes = parse_profile_nodes(&profile.payload)?;
        unsafe {
            replace_profile_node_options(state, &nodes);
        }
        Ok(())
    }

    fn switch_profile_node(state: &mut AppState) -> Result<(), String> {
        let selected_node_id = unsafe { selected_profile_node_id(state) };
        let (selected_node_id, outbound_tag) = state
            .profile_nodes
            .iter()
            .find(|node| node.id == selected_node_id)
            .map(|node| {
                let outbound_tag = node.selector_outbound_tag.clone().ok_or_else(|| {
                    "The selected node is not available in the managed sing-box selector"
                        .to_string()
                })?;
                Ok::<_, String>((node.id.clone(), outbound_tag))
            })
            .ok_or_else(|| {
                "Load nodes from the current profile before switching the active node".to_string()
            })??;
        let status = select_sing_box_clash_api_outbound(
            &SingBoxLocalControllerConfig::loopback_selector(),
            &outbound_tag,
        )
        .map_err(|error| error.to_string())?;
        if status.current_outbound_tag != outbound_tag {
            return Err("sing-box did not confirm the selected active node".to_string());
        }

        state.desktop.profile_node_id = Some(selected_node_id);
        save_desktop_state(&state.desktop)?;
        Ok(())
    }

    fn load_profile_payload(location: &str) -> Result<ProfilePayload, String> {
        if is_remote_subscription_url(location) {
            return Ok(ProfilePayload {
                payload: download_remote_subscription(location)?,
                source_path: None,
                source_url: Some(location.to_string()),
            });
        }
        let source_path = PathBuf::from(location);
        let payload = fs::read_to_string(&source_path)
            .map_err(|error| format!("Profile file could not be read: {error}"))?;
        Ok(ProfilePayload {
            payload,
            source_path: Some(source_path),
            source_url: None,
        })
    }

    fn parse_profile_nodes(payload: &str) -> Result<Vec<NodeDescriptor>, String> {
        let subscription = CoreSubscriptionService::new();
        let source = SubscriptionSource {
            id: "windows-gui-local-profile".to_string(),
            location: format!("inline:{payload}"),
        };
        let raw = subscription
            .fetch(&source)
            .map_err(|error| error.to_string())?;
        let document = subscription
            .parse(&raw)
            .map_err(|error| error.to_string())?;
        let catalog = subscription
            .normalize(&document)
            .map_err(|error| error.to_string())?;
        if catalog.nodes.is_empty() {
            return Err("Profile did not contain a supported proxy node".to_string());
        }
        Ok(catalog.nodes)
    }

    unsafe fn replace_profile_node_options(state: &mut AppState, nodes: &[NodeDescriptor]) {
        replace_profile_node_options_from_options(state, profile_node_options(nodes));
    }

    unsafe fn replace_profile_node_options_from_options(
        state: &mut AppState,
        profile_nodes: Vec<ProfileNodeOption>,
    ) {
        let selected_node_id = selected_profile_node_id(state);
        state.profile_nodes = profile_nodes;
        SendMessageW(state.profile_node_id, CB_RESETCONTENT, 0, 0);
        for option in &state.profile_nodes {
            let label = wide(&option.label);
            SendMessageW(
                state.profile_node_id,
                CB_ADDSTRING,
                0,
                label.as_ptr() as isize,
            );
        }
        let selected_index = state
            .profile_nodes
            .iter()
            .position(|option| option.id == selected_node_id)
            .or_else(|| selected_node_id.trim().is_empty().then_some(0));
        if let Some(index) = selected_index {
            SendMessageW(state.profile_node_id, CB_SETCURSEL, index, 0);
        } else {
            set_text(state.profile_node_id, &selected_node_id);
        }
    }

    unsafe fn clear_profile_node_options(state: &mut AppState) {
        state.profile_nodes.clear();
        SendMessageW(state.profile_node_id, CB_RESETCONTENT, 0, 0);
        set_text(state.profile_node_id, "");
    }

    unsafe fn selected_profile_node_id(state: &AppState) -> String {
        selected_profile_node_id_from_value(&state.profile_nodes, &get_text(state.profile_node_id))
    }

    fn profile_node_options(nodes: &[NodeDescriptor]) -> Vec<ProfileNodeOption> {
        nodes
            .iter()
            .enumerate()
            .map(|(index, node)| ProfileNodeOption {
                id: node.id.clone(),
                label: profile_node_label(node),
                selector_outbound_tag: Some(sing_box_local_selector_outbound_tag(index)),
            })
            .collect()
    }

    fn profile_node_options_from_selector(
        nodes: &[SingBoxLocalProxySelectableNode],
    ) -> Vec<ProfileNodeOption> {
        nodes
            .iter()
            .map(|node| ProfileNodeOption {
                id: node.id.clone(),
                label: format!("{} [{}]", node.name.replace(['\r', '\n'], " "), node.id),
                selector_outbound_tag: Some(node.outbound_tag.clone()),
            })
            .collect()
    }

    unsafe fn replace_profile_node_options_from_selector(
        state: &mut AppState,
        nodes: &[SingBoxLocalProxySelectableNode],
    ) {
        replace_profile_node_options_from_options(state, profile_node_options_from_selector(nodes));
    }

    fn selected_profile_node_id_from_value(options: &[ProfileNodeOption], value: &str) -> String {
        options
            .iter()
            .find(|option| option.label == value)
            .map(|option| option.id.clone())
            .unwrap_or_else(|| value.to_string())
    }

    fn profile_node_label(node: &NodeDescriptor) -> String {
        let name = node.name.replace(['\r', '\n'], " ");
        format!("{name} [{}]", node.id)
    }

    fn is_remote_subscription_url(location: &str) -> bool {
        location.trim().split_once(':').is_some_and(|(scheme, _)| {
            scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")
        })
    }

    fn download_remote_subscription(location: &str) -> Result<String, String> {
        let url =
            reqwest::Url::parse(location).map_err(|_| "Subscription URL is invalid".to_string())?;
        if !matches!(url.scheme(), "https" | "http") {
            return Err("Subscription URL must use HTTP or HTTPS".to_string());
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("AnixOps-NetworkCore/Windows")
            .build()
            .map_err(|_| "Subscription download client could not be created".to_string())?;
        let payload = client
            .get(url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|_| "Subscription download failed".to_string())?
            .text()
            .map_err(|_| "Subscription response could not be read".to_string())?;
        if payload.trim().is_empty() {
            return Err("Subscription response is empty".to_string());
        }
        Ok(payload)
    }

    fn stage_native_sing_box_mitm_config(
        config_path: &Path,
        original_json: &str,
        listen_port: u16,
    ) -> Result<PathBuf, String> {
        let rewritten =
            rewrite_sing_box_mixed_inbound_listener(original_json, "127.0.0.1", listen_port)
                .map_err(|error| error.to_string())?;
        let snapshot_path = windows_managed_data_directory()
            .join("mitm")
            .join("sing-box-config.before-mitm.json");
        write_managed_text_atomic(&snapshot_path, original_json).map_err(|error| {
            format!("Native sing-box MITM rollback snapshot could not be written: {error}")
        })?;
        write_managed_text_atomic(config_path, &rewritten).map_err(|error| {
            format!("Native sing-box configuration could not be prepared for HTTPS MITM: {error}")
        })?;
        Ok(snapshot_path)
    }

    fn rewrite_managed_sing_box_listen_port(
        sing_box: &mut WindowsManagedSingBoxConfig,
        listen_port: u16,
    ) -> Result<(), String> {
        let raw = fs::read_to_string(&sing_box.config_path).map_err(|error| {
            format!(
                "Managed sing-box config could not be read for HTTPS MITM reconfiguration: {error}"
            )
        })?;
        let rewritten = rewrite_sing_box_mixed_inbound_listener(&raw, "127.0.0.1", listen_port)
            .map_err(|error| error.to_string())?;
        write_managed_text_atomic(&sing_box.config_path, &rewritten).map_err(|error| {
            format!(
                "Managed sing-box config could not be written for HTTPS MITM reconfiguration: {error}"
            )
        })?;
        sing_box.enabled = true;
        Ok(())
    }

    fn ensure_mitm_ca_material() -> Result<(PathBuf, PathBuf), String> {
        let directory = windows_managed_data_directory().join("mitm");
        let certificate_path = directory.join("root-ca.pem");
        let private_key_path = directory.join("root-ca-key.pem");
        if certificate_path.exists() && private_key_path.exists() {
            return Ok((certificate_path, private_key_path));
        }
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, MITM_CA_SUBJECT);
        distinguished_name.push(DnType::OrganizationName, "AnixOps NetworkCore");
        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key_pair = KeyPair::generate().map_err(|error| error.to_string())?;
        let certificate = params
            .self_signed(&key_pair)
            .map_err(|error| error.to_string())?;
        fs::write(&certificate_path, certificate.pem()).map_err(|error| error.to_string())?;
        fs::write(&private_key_path, key_pair.serialize_pem())
            .map_err(|error| error.to_string())?;
        Ok((certificate_path, private_key_path))
    }

    fn stop_running_service_for_reconfigure(state: &mut AppState) -> Result<bool, String> {
        let status = state
            .integration
            .service_status()
            .map_err(|error| error.to_string())?;
        if status.state == WindowsServiceState::Running {
            stop_service(state)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn managed_config_or_default() -> Result<WindowsManagedConfig, String> {
        let path = windows_managed_config_path();
        if path.exists() {
            return read_managed_config(&path).map_err(|error| error.to_string());
        }
        Ok(WindowsManagedConfig {
            schema_version: WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
            system_proxy: None,
            root_certificate_path: None,
            driver_package: None,
            tunnel: None,
            sing_box: None,
            native_mitm: None,
        })
    }

    fn apply_user_proxy_from_config(state: &mut AppState) -> Result<(), String> {
        let config = read_managed_config(&windows_managed_config_path())
            .map_err(|error| error.to_string())?;
        if let Some(proxy) = config.system_proxy {
            if state.desktop.proxy_snapshot.is_none() {
                state.desktop.proxy_snapshot = Some(
                    state
                        .integration
                        .apply_system_proxy(&proxy)
                        .map_err(|error| error.to_string())?,
                );
                save_desktop_state(&state.desktop)?;
            }
        }
        Ok(())
    }

    fn enable_proxy(state: &mut AppState) -> Result<(), String> {
        if state.desktop.proxy_snapshot.is_some() {
            return Ok(());
        }
        let settings = WindowsProxySettings {
            enabled: true,
            server: unsafe { get_text(state.proxy_server) },
            bypass: unsafe { get_text(state.proxy_bypass) },
        };
        state.desktop.proxy_snapshot = Some(
            state
                .integration
                .apply_system_proxy(&settings)
                .map_err(|error| error.to_string())?,
        );
        save_desktop_state(&state.desktop)
    }

    fn restore_proxy(state: &mut AppState) -> Result<(), String> {
        if let Some(snapshot) = state.desktop.proxy_snapshot.take() {
            if let Err(error) = state.integration.restore_system_proxy(&snapshot) {
                state.desktop.proxy_snapshot = Some(snapshot);
                return Err(error.to_string());
            }
            save_desktop_state(&state.desktop)?;
        }
        Ok(())
    }

    fn install_certificate(state: &mut AppState) -> Result<(), String> {
        let path = PathBuf::from(unsafe { get_text(state.certificate_path) });
        state.desktop.certificate_sha1 = Some(
            state
                .integration
                .install_root_certificate(&path)
                .map_err(|error| error.to_string())?,
        );
        save_desktop_state(&state.desktop)
    }

    fn remove_certificate(state: &mut AppState) -> Result<(), String> {
        if let Some(thumbprint) = state.desktop.certificate_sha1.take() {
            if let Err(error) = state.integration.remove_root_certificate(&thumbprint) {
                state.desktop.certificate_sha1 = Some(thumbprint);
                return Err(error.to_string());
            }
            save_desktop_state(&state.desktop)?;
        }
        Ok(())
    }

    fn install_driver(state: &mut AppState) -> Result<(), String> {
        let path = PathBuf::from(unsafe { get_text(state.driver_path) });
        let installed = state
            .integration
            .install_driver(&path)
            .map_err(|error| error.to_string())?;
        state.desktop.driver_inf_path = Some(installed.inf_path);
        save_desktop_state(&state.desktop)
    }

    fn remove_driver(state: &mut AppState) -> Result<(), String> {
        if let Some(path) = state.desktop.driver_inf_path.take() {
            if let Err(error) = state.integration.uninstall_driver(&path) {
                state.desktop.driver_inf_path = Some(path);
                return Err(error.to_string());
            }
            save_desktop_state(&state.desktop)?;
        }
        Ok(())
    }

    fn load_configuration_fields(state: &mut AppState) {
        let path = windows_managed_config_path();
        if let Ok(config) = read_managed_config(&path) {
            unsafe {
                set_text(state.config_path, path.to_string_lossy().as_ref());
                if let Some(proxy) = config.system_proxy {
                    set_text(state.proxy_server, &proxy.server);
                    set_text(state.proxy_bypass, &proxy.bypass);
                }
                if let Some(certificate) = config.root_certificate_path {
                    set_text(
                        state.certificate_path,
                        certificate.to_string_lossy().as_ref(),
                    );
                }
                if let Some(native_mitm) = config.native_mitm {
                    set_text(
                        state.certificate_path,
                        native_mitm.ca_certificate_path.to_string_lossy().as_ref(),
                    );
                }
                if let Some(driver) = config.driver_package {
                    set_text(
                        state.driver_path,
                        driver.inf_path.to_string_lossy().as_ref(),
                    );
                }
            }
        }
    }

    fn desktop_state_path() -> PathBuf {
        windows_managed_data_directory().join(DESKTOP_STATE_FILE)
    }

    fn load_desktop_state() -> DesktopState {
        fs::read(desktop_state_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn save_desktop_state(state: &DesktopState) -> Result<(), String> {
        let path = desktop_state_path();
        let parent = path
            .parent()
            .ok_or_else(|| "desktop state path has no parent".to_string())?;
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
        fs::write(path, bytes).map_err(|error| error.to_string())
    }

    fn elevate(debug: bool) -> Result<(), String> {
        let executable = env::current_exe().map_err(|error| error.to_string())?;
        let executable = wide_os(&executable);
        let verb = wide("runas");
        let arguments = if debug { wide("--debug") } else { wide("") };
        let result = unsafe {
            ShellExecuteW(
                null_mut(),
                verb.as_ptr(),
                executable.as_ptr(),
                arguments.as_ptr(),
                null(),
                SW_SHOWNORMAL,
            )
        } as isize;
        if result <= 32 {
            return Err("Administrator elevation was not granted".to_string());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn create_label(
        parent: HWND,
        instance: HINSTANCE,
        font: *mut std::ffi::c_void,
        text: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> HWND {
        let control = create_control(
            parent,
            instance,
            "STATIC",
            text,
            WS_CHILD | WS_VISIBLE,
            0,
            x,
            y,
            width,
            height,
            0,
        );
        SendMessageW(control, WM_SETFONT, font as usize, 1);
        control
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn create_group(
        parent: HWND,
        instance: HINSTANCE,
        font: *mut std::ffi::c_void,
        text: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> HWND {
        let control = create_control(
            parent,
            instance,
            "BUTTON",
            text,
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX as u32,
            0,
            x,
            y,
            width,
            height,
            0,
        );
        SendMessageW(control, WM_SETFONT, font as usize, 1);
        control
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn create_button(
        parent: HWND,
        instance: HINSTANCE,
        font: *mut std::ffi::c_void,
        text: &str,
        id: usize,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> HWND {
        let control = create_control(
            parent,
            instance,
            "BUTTON",
            text,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0,
            x,
            y,
            width,
            height,
            id,
        );
        SendMessageW(control, WM_SETFONT, font as usize, 1);
        control
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn create_edit(
        parent: HWND,
        instance: HINSTANCE,
        font: *mut std::ffi::c_void,
        text: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> HWND {
        let control = create_control(
            parent,
            instance,
            "EDIT",
            text,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32,
            0,
            x,
            y,
            width,
            height,
            0,
        );
        SendMessageW(control, WM_SETFONT, font as usize, 1);
        control
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn create_profile_node_selector(
        parent: HWND,
        instance: HINSTANCE,
        font: *mut std::ffi::c_void,
        text: &str,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> HWND {
        let control = create_control(
            parent,
            instance,
            "COMBOBOX",
            text,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWN as u32,
            0,
            x,
            y,
            width,
            height + 160,
            0,
        );
        SendMessageW(control, WM_SETFONT, font as usize, 1);
        control
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn create_control(
        parent: HWND,
        instance: HINSTANCE,
        class_name: &str,
        text: &str,
        style: u32,
        extended_style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        id: usize,
    ) -> HWND {
        let class_name = wide(class_name);
        let text = wide(text);
        CreateWindowExW(
            extended_style,
            class_name.as_ptr(),
            text.as_ptr(),
            style,
            x,
            y,
            width,
            height,
            parent,
            id as HMENU,
            instance,
            null(),
        )
    }

    unsafe fn set_text(control: HWND, text: &str) {
        let text = wide(text);
        SetWindowTextW(control, text.as_ptr());
    }

    unsafe fn get_text(control: HWND) -> String {
        let length = GetWindowTextLengthW(control);
        let mut buffer = vec![0u16; length as usize + 1];
        GetWindowTextW(control, buffer.as_mut_ptr(), buffer.len() as i32);
        String::from_utf16_lossy(&buffer[..length as usize])
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    fn wide_os(value: &Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        value.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn last_error(message: &str) -> String {
        format!("{message} (win32={})", unsafe { GetLastError() })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use control_domain::{Endpoint, Protocol};

        fn node(id: &str, name: &str) -> NodeDescriptor {
            NodeDescriptor {
                id: id.to_string(),
                name: name.to_string(),
                protocol: Protocol::Shadowsocks,
                endpoint: Endpoint {
                    host: "edge.example.test".to_string(),
                    port: 443,
                },
                tags: Vec::new(),
                metadata: Vec::new(),
            }
        }

        #[test]
        fn profile_selector_maps_display_label_to_stable_node_id() {
            let nodes = vec![
                node("primary-node", "Primary\nnode"),
                node("backup-node", "Backup"),
            ];
            let options = profile_node_options(&nodes);

            assert_eq!(options[0].label, "Primary node [primary-node]");
            assert_eq!(
                options[0].selector_outbound_tag.as_deref(),
                Some("networkcore-node-0")
            );
            assert_eq!(
                selected_profile_node_id_from_value(&options, &options[0].label),
                "primary-node"
            );
            assert_eq!(
                selected_profile_node_id_from_value(&options, "manual-node-id"),
                "manual-node-id"
            );
        }
    }
}
