#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("networkcore-windows-gui requires Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if std::env::args().any(|argument| argument == "--cleanup-startup") {
        if let Err(error) = gui::cleanup_current_user_startup() {
            gui::show_fatal_error(&error);
            std::process::exit(1);
        }
        return;
    }
    let debug = std::env::args().any(|argument| argument == "--debug" || argument == "-d");
    if let Err(error) = gui::run(debug) {
        gui::show_fatal_error(&error);
    }
}

#[cfg(windows)]
mod gui {
    mod actions;
    mod commands;
    mod pages;
    mod runtime_status;
    mod shell;
    mod startup;
    mod theme;
    mod tray;
    mod ui_state;
    mod widgets;

    use self::actions::connection as connection_actions;
    use self::commands::{dispatch as dispatch_command, CommandCompletion};
    use self::pages::{home as home_page, settings as settings_page};
    use self::runtime_status::{read_runtime_status, WindowsRuntimeStatus};
    use self::shell::DailyShell;
    use self::startup::{
        load_desktop_state, owns_current_proxy, save_desktop_state, DesktopProfileNode,
        DesktopState,
    };
    use self::theme::ThemeMode;
    use self::tray::{TrayCommandIds, TrayMenuState};
    use self::ui_state::{can_start_operation, user_facing_error, OperationKind, UiPage};
    use self::widgets::{checkbox_checked, last_error, set_text, text as get_text, wide, wide_os};
    use config_core::CoreSubscriptionService;
    use control_domain::{NodeDescriptor, SubscriptionService, SubscriptionSource};
    use engine_singbox::{
        inspect_sing_box_local_selector_snapshot, inspect_sing_box_native_config,
        measure_sing_box_clash_api_outbound_delay, read_sing_box_clash_api_selector,
        render_sing_box_local_proxy_selector_config, rewrite_sing_box_mixed_inbound_listener,
        select_sing_box_clash_api_outbound, sing_box_config_sha256,
        sing_box_local_selector_outbound_tag, GithubSingBoxReleaseInstaller, SingBoxInstallRequest,
        SingBoxLocalControllerConfig, SingBoxLocalProxyConfigRequest,
        SingBoxLocalProxySelectableNode, SingBoxManagedProcessRequest,
        SingBoxManagedProcessSupervisor, SingBoxReleaseInstaller, SingBoxTarget, SingBoxTargetArch,
        SingBoxTargetOs, DEFAULT_SING_BOX_CLASH_API_DELAY_TIMEOUT_MILLIS,
    };
    use platform_windows::managed::{
        append_managed_log, read_managed_config, read_managed_state, windows_managed_config_path,
        windows_managed_data_directory, windows_managed_log_directory, windows_managed_state_path,
        write_managed_config, write_managed_state, write_managed_text_atomic, WindowsManagedConfig,
        WindowsManagedNativeMitmConfig, WindowsManagedSingBoxConfig, WindowsProxySettings,
        WindowsSystemProxyOwner, WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
    };
    use platform_windows::system_integration::{
        current_user_startup_enabled, disable_current_user_startup, enable_current_user_startup,
        read_current_user_system_proxy, NativeWindowsSystemIntegration, WindowsServiceState,
        WindowsSystemIntegration,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::env;
    use std::fs;
    use std::mem::zeroed;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{GlobalFree, HWND, LPARAM, LRESULT, SYSTEMTIME, WPARAM};
    use windows_sys::Win32::Graphics::Gdi::{
        CreateSolidBrush, DeleteObject, GetStockObject, InvalidateRect, SetBkColor, SetTextColor,
        UpdateWindow, COLOR_WINDOW, DEFAULT_GUI_FONT, HBRUSH,
    };
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        GetWindowLongPtrW, KillTimer, LoadCursorW, MessageBoxW, PostQuitMessage, RegisterClassW,
        SendMessageW, SetTimer, SetWindowLongPtrW, ShowWindow, TranslateMessage, BM_SETCHECK,
        CB_ADDSTRING, CB_RESETCONTENT, CB_SETCURSEL, CW_USEDEFAULT, GWLP_USERDATA, IDC_ARROW, IDOK,
        MB_ICONERROR, MB_ICONINFORMATION, MB_OK, MB_OKCANCEL, MINMAXINFO, MSG, SW_HIDE, SW_SHOW,
        SW_SHOWNORMAL, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_CTLCOLORBTN, WM_CTLCOLOREDIT,
        WM_CTLCOLORLISTBOX, WM_CTLCOLORSTATIC, WM_DESTROY, WM_GETMINMAXINFO, WM_NCDESTROY,
        WM_TIMER, WNDCLASSW, WS_CAPTION, WS_CLIPCHILDREN, WS_MAXIMIZEBOX, WS_OVERLAPPED,
        WS_SYSMENU, WS_THICKFRAME,
    };

    const APP_CLASS: &str = "AnixOpsNetworkCoreWindow";
    const APP_TITLE: &str = "AnixOps NetworkCore";
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
    const ID_RESTORE_PROXY: usize = 121;
    const ID_TEST_PROFILE_NODE_DELAY: usize = 122;
    const ID_CHECK_PROFILE_RUNTIME: usize = 123;
    const ID_INSTALL_CERTIFICATE: usize = 130;
    const ID_REMOVE_CERTIFICATE: usize = 131;
    const ID_INSTALL_DRIVER: usize = 140;
    const ID_REMOVE_DRIVER: usize = 141;
    const ID_TOGGLE_DEBUG: usize = 150;
    const ID_OPEN_LOGS: usize = 151;
    const ID_OPEN_CORE_LOG: usize = 152;
    const ID_SHOW_DIAGNOSTICS: usize = 153;
    const ID_COPY_DIAGNOSTICS: usize = 154;
    const ID_CONNECT: usize = 160;
    const ID_DISCONNECT: usize = 161;
    const ID_EXIT: usize = 162;
    const ID_START_AFTER_LOGIN: usize = 163;
    const ID_AUTO_CONNECT: usize = 164;
    const ID_AUTO_RECOVER_CORE: usize = 165;
    const ID_NAV_HOME: usize = 170;
    const ID_NAV_NODES: usize = 171;
    const ID_NAV_SUBSCRIPTIONS: usize = 172;
    const ID_NAV_SETTINGS: usize = 173;
    const ID_NAV_DIAGNOSTICS: usize = 174;
    const ID_NAV_ADVANCED: usize = 175;
    const ID_TOGGLE_THEME: usize = 176;
    const ID_FILTER_PROFILE_NODES: usize = 177;
    const BACKGROUND_TIMER_ID: usize = 1;
    const BACKGROUND_TIMER_INTERVAL_MILLIS: u32 = 150;

    const SING_BOX_DIRECT_LISTEN_PORT: u16 = 7890;
    const SING_BOX_MITM_UPSTREAM_PORT: u16 = 7891;
    const NATIVE_MITM_LISTEN_PORT: u16 = 7890;
    const MITM_CA_SUBJECT: &str = "AnixOps NetworkCore Windows HTTPS MITM CA";

    struct ThemeBrushes {
        surface: HBRUSH,
    }

    impl ThemeBrushes {
        unsafe fn new(mode: ThemeMode) -> Self {
            Self {
                surface: CreateSolidBrush(self::theme::palette(mode).surface),
            }
        }
    }

    impl Drop for ThemeBrushes {
        fn drop(&mut self) {
            if !self.surface.is_null() {
                unsafe {
                    DeleteObject(self.surface as _);
                }
            }
        }
    }

    struct AppState {
        window: HWND,
        integration: NativeWindowsSystemIntegration,
        service_status: HWND,
        activity: HWND,
        debug_status: HWND,
        config_path: HWND,
        profile_source: HWND,
        profile_node_id: HWND,
        delay_test_url: HWND,
        profile_delay_status: HWND,
        profile_runtime_status: HWND,
        certificate_path: HWND,
        driver_path: HWND,
        desktop: DesktopState,
        profile_nodes: Vec<DesktopProfileNode>,
        profile_node_catalog: Vec<DesktopProfileNode>,
        current_page: UiPage,
        daily: Option<DailyShell>,
        theme: ThemeMode,
        theme_brushes: ThemeBrushes,
        pending_operation: Option<OperationKind>,
        command_sender: Sender<CommandCompletion<BackgroundPayload>>,
        command_receiver: Receiver<CommandCompletion<BackgroundPayload>>,
        last_runtime_refresh: Instant,
        runtime: WindowsRuntimeStatus,
        auto_connect_attempted: bool,
        core_recovery_attempted: bool,
        gui_started_connection: bool,
        exit_after_disconnect: bool,
    }

    struct ImportedSingBoxProfile {
        executable_path: PathBuf,
        config_path: PathBuf,
        config_parent: PathBuf,
        local_http_proxy: Option<String>,
        sing_box_config_snapshot_path: Option<PathBuf>,
        source_path: Option<PathBuf>,
        source_url: Option<String>,
        selected_node_id: Option<String>,
        node_catalog: Vec<DesktopProfileNode>,
        config_sha256: Option<String>,
    }

    struct ProfilePayload {
        payload: String,
        source_path: Option<PathBuf>,
        source_url: Option<String>,
    }

    enum BackgroundPayload {
        Connected(connection_actions::ConnectedProxy),
        Service(String),
        CoreInstalled(PathBuf),
        ConfigurationValidated,
        NodesLoaded(Vec<DesktopProfileNode>),
        ProfileLoaded(ProfilePayload),
        NodeSwitched(String),
        DelayMeasured(String),
        CoreChecked(String),
        DiagnosticReport(PathBuf),
        StartupConfigured(bool),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ProfileRenderMode {
        Direct,
        NativeMitm,
    }

    pub fn run(debug: bool) -> Result<(), String> {
        let _ = append_managed_log("gui", &format!("startup debug={debug}"));
        if unsafe { IsUserAnAdmin() } == 0 {
            let start_after_login =
                std::env::args().any(|argument| argument == "--start-after-login");
            if !request_elevation(debug, start_after_login)? {
                let _ = append_managed_log("gui", "administrator elevation was declined");
            }
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
                WS_OVERLAPPED
                    | WS_CAPTION
                    | WS_SYSMENU
                    | WS_THICKFRAME
                    | WS_MAXIMIZEBOX
                    | WS_CLIPCHILDREN,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                1_180,
                820,
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

    pub fn cleanup_current_user_startup() -> Result<(), String> {
        let executable = env::current_exe().map_err(|error| error.to_string())?;
        disable_current_user_startup(&executable).map_err(|error| error.to_string())
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
                    SetTimer(
                        window,
                        BACKGROUND_TIMER_ID,
                        BACKGROUND_TIMER_INTERVAL_MILLIS,
                        None,
                    );
                    if let Err(error) = self::tray::add(window) {
                        show_fatal_error(&error);
                        DestroyWindow(window);
                        return -1;
                    }
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
            self::tray::TRAY_CALLBACK_MESSAGE => {
                with_state(window, |state| handle_tray_callback(state, lparam));
                0
            }
            WM_TIMER if wparam == BACKGROUND_TIMER_ID => {
                with_state(window, |state| poll_background_commands(state));
                0
            }
            WM_GETMINMAXINFO => {
                let info = &mut *(lparam as *mut MINMAXINFO);
                info.ptMinTrackSize.x = 1_100;
                info.ptMinTrackSize.y = 760;
                0
            }
            WM_CTLCOLORSTATIC | WM_CTLCOLORBTN | WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX => {
                let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut AppState;
                if pointer.is_null() {
                    return DefWindowProcW(window, message, wparam, lparam);
                }
                let state = &mut *pointer;
                let palette = self::theme::palette(state.theme);
                SetTextColor(wparam as _, palette.text);
                SetBkColor(wparam as _, palette.surface);
                state.theme_brushes.surface as isize
            }
            WM_CLOSE => {
                ShowWindow(window, SW_HIDE);
                0
            }
            WM_DESTROY => {
                KillTimer(window, BACKGROUND_TIMER_ID);
                self::tray::remove(window);
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
        let mut desktop = load_desktop_state()?;
        if std::env::args().any(|argument| argument == "--debug" || argument == "-d") {
            desktop.debug_enabled = true;
        }
        let theme = if desktop.dark_theme {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        };
        let (command_sender, command_receiver) = mpsc::channel();
        let shell = self::shell::create(window, instance, font, &desktop);
        let mut state = Box::new(AppState {
            window,
            integration: NativeWindowsSystemIntegration::new(),
            service_status: shell.home_service,
            activity: shell.activity,
            debug_status: shell.debug_status,
            config_path: shell.config_path,
            profile_source: shell.profile_source,
            profile_node_id: shell.profile_node_id,
            delay_test_url: shell.delay_test_url,
            profile_delay_status: shell.profile_delay_status,
            profile_runtime_status: shell.profile_runtime_status,
            certificate_path: shell.certificate_path,
            driver_path: shell.driver_path,
            desktop,
            profile_nodes: Vec::new(),
            profile_node_catalog: Vec::new(),
            current_page: UiPage::Home,
            daily: Some(shell),
            theme,
            theme_brushes: ThemeBrushes::new(theme),
            pending_operation: None,
            command_sender,
            command_receiver,
            last_runtime_refresh: Instant::now(),
            runtime: read_runtime_status(),
            auto_connect_attempted: false,
            core_recovery_attempted: false,
            gui_started_connection: false,
            exit_after_disconnect: false,
        });
        if let Err(error) = sync_startup_state(&mut state) {
            set_text(
                state.activity,
                &format!("Startup setting unavailable: {error}"),
            );
            if let Some(shell) = state.daily.as_ref() {
                EnableWindow(shell.start_after_login, 0);
            }
            let _ = append_managed_log("gui", &format!("startup setting query failed: {error}"));
        }
        save_desktop_state(&state.desktop)?;
        load_configuration_fields(&mut state);
        if let Err(error) = restore_saved_profile_node_catalog(&mut state) {
            let message = format!("Saved node catalog could not be restored: {error}");
            set_text(state.activity, &message);
            let _ = append_managed_log("gui", &message);
        }
        update_debug_status(&mut state);
        switch_page(&mut state, UiPage::Home);
        refresh(&mut state);
        Ok(state)
    }

    unsafe fn handle_command(state: &mut AppState, id: usize) {
        match id {
            ID_NAV_HOME => {
                ShowWindow(state.window, SW_SHOWNORMAL);
                switch_page(state, UiPage::Home);
            }
            ID_NAV_NODES => switch_page(state, UiPage::Nodes),
            ID_NAV_SUBSCRIPTIONS => switch_page(state, UiPage::Subscriptions),
            ID_NAV_SETTINGS => switch_page(state, UiPage::Settings),
            ID_NAV_DIAGNOSTICS => switch_page(state, UiPage::Diagnostics),
            ID_NAV_ADVANCED => switch_page(state, UiPage::Advanced),
            ID_TOGGLE_THEME => toggle_theme(state),
            ID_FILTER_PROFILE_NODES => filter_profile_nodes(state),
            ID_CONNECT | ID_START_SERVICE => submit_service_start(state),
            ID_DISCONNECT | ID_STOP_SERVICE => submit_service_stop(state),
            ID_EXIT => request_exit(state),
            ID_START_AFTER_LOGIN => submit_startup_toggle(state),
            ID_AUTO_CONNECT => update_auto_connect_preference(state),
            ID_AUTO_RECOVER_CORE => update_auto_recovery_preference(state),
            ID_RESTART_SERVICE => submit_service_restart(state),
            ID_REFRESH => refresh(state),
            ID_INSTALL_SERVICE => run_action(state, "Service installed", install_service),
            ID_APPLY_CONFIG => run_action(state, "Configuration applied", apply_configuration),
            ID_OPEN_MANAGED_CONFIG => {
                run_action(state, "Configuration opened", open_managed_config)
            }
            ID_VALIDATE_CONFIGURATION => submit_configuration_validation(state),
            ID_INSTALL_SING_BOX => submit_core_install(state),
            ID_LOAD_PROFILE_NODES => submit_profile_node_load(state),
            ID_IMPORT_PROFILE => submit_profile_import(state, false),
            ID_SWITCH_PROFILE_NODE => submit_profile_node_switch(state),
            ID_TEST_PROFILE_NODE_DELAY => submit_profile_node_delay_test(state),
            ID_CHECK_PROFILE_RUNTIME => submit_profile_runtime_check(state),
            ID_UPDATE_PROFILE => submit_profile_import(state, true),
            ID_ENABLE_HTTPS_MITM => run_action(state, "HTTPS MITM configured", enable_https_mitm),
            ID_DISABLE_HTTPS_MITM => run_action(state, "HTTPS MITM disabled", disable_https_mitm),
            ID_RESTORE_PROXY => run_action(state, "Network settings restored", restore_proxy),
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
            ID_SHOW_DIAGNOSTICS => submit_diagnostics(state),
            ID_COPY_DIAGNOSTICS => {
                run_action(state, "Diagnostic summary copied", copy_diagnostic_summary)
            }
            _ => {}
        }
    }

    unsafe fn handle_tray_callback(state: &mut AppState, lparam: LPARAM) {
        let node = selected_node_label(state);
        let command = self::tray::handle_callback(
            state.window,
            lparam,
            TrayMenuState {
                connection: state.runtime.connection,
                busy: state.pending_operation.is_some(),
                has_gui_owned_proxy: state.desktop.proxy_snapshot.is_some(),
            },
            state.runtime.connection.label(),
            &node,
            TrayCommandIds {
                open: ID_NAV_HOME,
                connect: ID_CONNECT,
                disconnect: ID_DISCONNECT,
                refresh: ID_REFRESH,
                exit: ID_EXIT,
            },
        );
        if let Some(command) = command {
            handle_command(state, command);
        }
    }

    unsafe fn request_exit(state: &mut AppState) {
        if state.pending_operation.is_some() {
            set_text(
                state.activity,
                "Wait for the current operation before exiting NetworkCore.",
            );
            return;
        }
        if state.desktop.proxy_snapshot.is_none()
            && !matches!(
                state.runtime.service_state,
                WindowsServiceState::Running
                    | WindowsServiceState::StartPending
                    | WindowsServiceState::StopPending
            )
        {
            DestroyWindow(state.window);
            return;
        }
        state.exit_after_disconnect = true;
        submit_service_stop(state);
    }

    unsafe fn submit_startup_toggle(state: &mut AppState) {
        let Some(control) = state.daily.as_ref().map(|shell| shell.start_after_login) else {
            return;
        };
        let enabled = checkbox_checked(control);
        submit_background(state, OperationKind::Startup, move || {
            let executable = env::current_exe().map_err(|error| error.to_string())?;
            if enabled {
                enable_current_user_startup(&executable).map_err(|error| error.to_string())?;
            } else {
                disable_current_user_startup(&executable).map_err(|error| error.to_string())?;
            }
            let actual =
                current_user_startup_enabled(&executable).map_err(|error| error.to_string())?;
            if actual != enabled {
                return Err(
                    "Windows did not retain the requested current-user startup state".to_string(),
                );
            }
            Ok(BackgroundPayload::StartupConfigured(actual))
        });
    }

    unsafe fn update_auto_connect_preference(state: &mut AppState) {
        let Some(control) = state.daily.as_ref().map(|shell| shell.auto_connect) else {
            return;
        };
        let previous = state.desktop.auto_connect;
        state.desktop.auto_connect = checkbox_checked(control);
        if let Err(error) = save_desktop_state(&state.desktop) {
            state.desktop.auto_connect = previous;
            SendMessageW(control, BM_SETCHECK, usize::from(previous), 0);
            set_text(state.activity, &error);
            return;
        }
        set_text(
            state.activity,
            settings_page::daily_lifecycle_summary(
                state.desktop.start_after_login,
                state.desktop.auto_connect,
                state.desktop.auto_recover_core,
            ),
        );
    }

    unsafe fn update_auto_recovery_preference(state: &mut AppState) {
        let Some(control) = state.daily.as_ref().map(|shell| shell.auto_recover_core) else {
            return;
        };
        let previous = state.desktop.auto_recover_core;
        state.desktop.auto_recover_core = checkbox_checked(control);
        if let Err(error) = save_desktop_state(&state.desktop) {
            state.desktop.auto_recover_core = previous;
            SendMessageW(control, BM_SETCHECK, usize::from(previous), 0);
            set_text(state.activity, &error);
            return;
        }
        set_text(
            state.activity,
            settings_page::daily_lifecycle_summary(
                state.desktop.start_after_login,
                state.desktop.auto_connect,
                state.desktop.auto_recover_core,
            ),
        );
    }

    unsafe fn switch_page(state: &mut AppState, page: UiPage) {
        let Some(shell) = state.daily.as_ref() else {
            return;
        };
        for (candidate, panel) in [
            (UiPage::Home, shell.panels.home),
            (UiPage::Nodes, shell.panels.nodes),
            (UiPage::Subscriptions, shell.panels.subscriptions),
            (UiPage::Settings, shell.panels.settings),
            (UiPage::Diagnostics, shell.panels.diagnostics),
            (UiPage::Advanced, shell.panels.advanced),
        ] {
            ShowWindow(panel, if candidate == page { SW_SHOW } else { SW_HIDE });
        }
        state.current_page = page;
        set_text(shell.page_title, page.title());
    }

    unsafe fn toggle_theme(state: &mut AppState) {
        let mode = state.theme.toggled();
        state.desktop.dark_theme = mode == ThemeMode::Dark;
        if let Err(error) = save_desktop_state(&state.desktop) {
            set_text(state.activity, &error);
            return;
        }
        if let Some(shell) = state.daily.as_ref() {
            set_text(
                shell.theme_button,
                if mode == ThemeMode::Dark {
                    "Use light mode"
                } else {
                    "Use dark mode"
                },
            );
        }
        state.theme = mode;
        state.theme_brushes = ThemeBrushes::new(mode);
        InvalidateRect(state.window, null(), 1);
        set_text(state.activity, &format!("{} mode applied.", mode.label()));
    }

    unsafe fn filter_profile_nodes(state: &mut AppState) {
        let Some(shell) = state.daily.as_ref() else {
            return;
        };
        let search = get_text(shell.nodes_search).to_ascii_lowercase();
        let protocol = get_text(shell.nodes_protocol_filter).to_ascii_lowercase();
        let visible = state
            .profile_node_catalog
            .iter()
            .filter(|node| {
                (search.is_empty() || node.label.to_ascii_lowercase().contains(&search))
                    && (protocol == "all" || node.protocol.to_ascii_lowercase() == protocol)
            })
            .cloned()
            .collect::<Vec<_>>();
        replace_profile_node_selector_items(state, visible);
        set_text(
            state.activity,
            &format!("Showing {} matching node(s)", state.profile_nodes.len()),
        );
    }

    unsafe fn submit_service_start(state: &mut AppState) {
        if !connection_actions::can_connect(state.runtime.connection) {
            set_text(
                state.activity,
                "NetworkCore is already connected or connecting.",
            );
            return;
        }
        let config_path = PathBuf::from(get_text(state.config_path));
        let desktop = state.desktop.clone();
        submit_background(state, OperationKind::Connect, move || {
            connection_actions::connect(config_path, desktop).map(BackgroundPayload::Connected)
        });
    }

    unsafe fn submit_service_stop(state: &mut AppState) {
        if !connection_actions::can_disconnect(
            state.runtime.connection,
            state.desktop.proxy_snapshot.is_some(),
        ) {
            if state.exit_after_disconnect {
                DestroyWindow(state.window);
            } else {
                set_text(state.activity, "NetworkCore is already disconnected.");
            }
            return;
        }
        let desktop = state.desktop.clone();
        submit_background(state, OperationKind::Disconnect, move || {
            connection_actions::disconnect(desktop).map(BackgroundPayload::Service)
        });
    }

    unsafe fn submit_service_restart(state: &mut AppState) {
        submit_background(state, OperationKind::Service, move || {
            NativeWindowsSystemIntegration::new()
                .restart_service()
                .map_err(|error| error.to_string())?;
            Ok(BackgroundPayload::Service(
                "Service restart request submitted. Waiting for verification.".to_string(),
            ))
        });
    }

    unsafe fn submit_configuration_validation(state: &mut AppState) {
        let config_path = PathBuf::from(get_text(state.config_path));
        submit_background(state, OperationKind::ConfigurationCheck, move || {
            validate_managed_configuration(&config_path)?;
            Ok(BackgroundPayload::ConfigurationValidated)
        });
    }

    unsafe fn submit_core_install(state: &mut AppState) {
        submit_background(state, OperationKind::CoreInstall, move || {
            let installer =
                GithubSingBoxReleaseInstaller::new().map_err(|error| error.to_string())?;
            let report = installer
                .install_latest(&SingBoxInstallRequest {
                    install_root: windows_managed_data_directory()
                        .join("sing-box")
                        .join("engine"),
                    target: SingBoxTarget::new(SingBoxTargetOs::Windows, SingBoxTargetArch::Amd64),
                    force: false,
                })
                .map_err(|error| error.to_string())?;
            Ok(BackgroundPayload::CoreInstalled(report.executable_path))
        });
    }

    unsafe fn submit_profile_node_load(state: &mut AppState) {
        let location = get_text(state.profile_source).trim().to_string();
        submit_background(state, OperationKind::NodeCatalogLoad, move || {
            if location.is_empty() {
                return Err("Profile file path or subscription URL is required".to_string());
            }
            let profile = load_profile_payload(&location)?;
            if inspect_sing_box_native_config(&profile.payload).is_some() {
                return Err(
                    "Native sing-box JSON is passed through unchanged and has no generated node selector"
                        .to_string(),
                );
            }
            let nodes = parse_profile_nodes(&profile.payload)?;
            Ok(BackgroundPayload::NodesLoaded(profile_node_options(&nodes)))
        });
    }

    unsafe fn submit_profile_import(state: &mut AppState, update_saved_url: bool) {
        if !matches!(
            state.runtime.service_state,
            WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
        ) {
            set_text(
                state.activity,
                "Disconnect before importing or updating a profile so the running core keeps its active configuration.",
            );
            return;
        }
        let location = if update_saved_url {
            match state
                .desktop
                .profile_source_url
                .clone()
                .filter(|location| !location.trim().is_empty())
            {
                Some(location) => location,
                None => {
                    set_text(
                        state.activity,
                        "Import an HTTP or HTTPS subscription URL before updating it.",
                    );
                    return;
                }
            }
        } else {
            get_text(state.profile_source).trim().to_string()
        };
        let operation = if update_saved_url {
            OperationKind::SubscriptionUpdate
        } else {
            OperationKind::ProfileImport
        };
        submit_background(state, operation, move || {
            if location.is_empty() {
                return Err("Profile file path or subscription URL is required".to_string());
            }
            load_profile_payload(&location).map(BackgroundPayload::ProfileLoaded)
        });
    }

    unsafe fn submit_profile_node_switch(state: &mut AppState) {
        let selected_node_id = selected_profile_node_id(state);
        let outbound_tag = state
            .profile_nodes
            .iter()
            .find(|node| node.id == selected_node_id)
            .map(|node| node.outbound_tag.clone());
        submit_background(state, OperationKind::NodeSwitch, move || {
            let outbound_tag = outbound_tag.ok_or_else(|| {
                "Load nodes from the current profile before switching the active node".to_string()
            })?;
            let status = select_sing_box_clash_api_outbound(
                &SingBoxLocalControllerConfig::loopback_selector(),
                &outbound_tag,
            )
            .map_err(|error| error.to_string())?;
            if status.current_outbound_tag != outbound_tag {
                return Err("sing-box did not confirm the selected active node".to_string());
            }
            Ok(BackgroundPayload::NodeSwitched(selected_node_id))
        });
    }

    unsafe fn submit_profile_node_delay_test(state: &mut AppState) {
        let selected_node_id = selected_profile_node_id(state);
        let outbound_tag = state
            .profile_nodes
            .iter()
            .find(|node| node.id == selected_node_id)
            .map(|node| node.outbound_tag.clone());
        let test_url = get_text(state.delay_test_url);
        submit_background(state, OperationKind::DelayTest, move || {
            let outbound_tag = outbound_tag.ok_or_else(|| {
                "Load nodes from the current profile before testing the selected node".to_string()
            })?;
            let report = measure_sing_box_clash_api_outbound_delay(
                &SingBoxLocalControllerConfig::loopback_selector(),
                &outbound_tag,
                &test_url,
                DEFAULT_SING_BOX_CLASH_API_DELAY_TIMEOUT_MILLIS,
            )
            .map_err(|error| error.to_string())?;
            Ok(BackgroundPayload::DelayMeasured(format!(
                "{} ms|{}",
                report.delay_millis, report.test_url
            )))
        });
    }

    unsafe fn submit_profile_runtime_check(state: &mut AppState) {
        let nodes = state.profile_node_catalog.clone();
        submit_background(state, OperationKind::Diagnostics, move || {
            let status = read_sing_box_clash_api_selector(
                &SingBoxLocalControllerConfig::loopback_selector(),
            )
            .map_err(|error| error.to_string())?;
            if !status
                .outbound_tags
                .iter()
                .any(|outbound_tag| outbound_tag == &status.current_outbound_tag)
            {
                return Err(
                    "sing-box controller returned an active outbound outside the generated selector"
                        .to_string(),
                );
            }
            let active = nodes
                .iter()
                .find(|node| node.outbound_tag == status.current_outbound_tag)
                .map(|node| node.label.clone())
                .unwrap_or(status.current_outbound_tag);
            Ok(BackgroundPayload::CoreChecked(format!(
                "Ready: {active} ({} nodes)",
                status.outbound_tags.len()
            )))
        });
    }

    unsafe fn submit_diagnostics(state: &mut AppState) {
        let config_path = PathBuf::from(get_text(state.config_path));
        submit_background(state, OperationKind::Diagnostics, move || {
            write_diagnostic_report_at(&config_path).map(BackgroundPayload::DiagnosticReport)
        });
    }

    unsafe fn submit_background<F>(state: &mut AppState, operation: OperationKind, task: F)
    where
        F: FnOnce() -> Result<BackgroundPayload, String> + Send + 'static,
    {
        if !can_start_operation(state.pending_operation) {
            let active = state
                .pending_operation
                .expect("operation presence was checked");
            set_text(
                state.activity,
                &format!("{} is already in progress", active.label()),
            );
            return;
        }
        state.pending_operation = Some(operation);
        EnableWindow(state.window, 0);
        set_text(state.activity, &format!("{}...", operation.label()));
        if let Some(shell) = state.daily.as_ref() {
            set_text(shell.status_summary, &format!("{}...", operation.label()));
        }
        dispatch_command(state.command_sender.clone(), operation, task);
    }

    unsafe fn poll_background_commands(state: &mut AppState) {
        loop {
            match state.command_receiver.try_recv() {
                Ok(completion) => apply_background_completion(state, completion),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        if state.pending_operation.is_none()
            && state.last_runtime_refresh.elapsed() >= Duration::from_secs(2)
        {
            refresh(state);
            state.last_runtime_refresh = Instant::now();
        }
    }

    unsafe fn apply_background_completion(
        state: &mut AppState,
        completion: CommandCompletion<BackgroundPayload>,
    ) {
        state.pending_operation = None;
        EnableWindow(state.window, 1);
        match completion.result {
            Ok(BackgroundPayload::Connected(connection_actions::ConnectedProxy {
                snapshot,
                applied_proxy,
            })) => {
                state.desktop.proxy_snapshot = Some(snapshot);
                state.desktop.applied_proxy = Some(applied_proxy);
                state.gui_started_connection = true;
                set_text(
                    state.activity,
                    "Connected. The managed core and current-user system proxy were verified.",
                );
            }
            Ok(BackgroundPayload::Service(message)) => {
                if completion.operation == OperationKind::Disconnect {
                    state.desktop.proxy_snapshot = None;
                    state.desktop.applied_proxy = None;
                    state.gui_started_connection = false;
                    if let Err(error) = save_desktop_state(&state.desktop) {
                        set_text(state.activity, &error);
                        return;
                    }
                }
                set_text(state.activity, &message);
                if state.exit_after_disconnect {
                    DestroyWindow(state.window);
                    return;
                }
            }
            Ok(BackgroundPayload::CoreInstalled(path)) => {
                state.desktop.sing_box_executable_path = Some(path.clone());
                let _ = save_desktop_state(&state.desktop);
                set_text(
                    state.activity,
                    &format!("sing-box installed at {}", path.display()),
                );
            }
            Ok(BackgroundPayload::ConfigurationValidated) => {
                set_text(
                    state.activity,
                    "Configuration is valid. sing-box preflight completed when enabled.",
                );
            }
            Ok(BackgroundPayload::NodesLoaded(nodes)) => {
                replace_profile_node_options_from_options(state, nodes);
                set_text(
                    state.activity,
                    "Subscription nodes loaded. Select a node before importing or switching.",
                );
            }
            Ok(BackgroundPayload::ProfileLoaded(profile)) => {
                match import_profile_payload(state, profile) {
                    Ok(()) => set_text(state.activity, "sing-box profile imported."),
                    Err(error) => {
                        if completion.operation == OperationKind::SubscriptionUpdate {
                            state.desktop.profile_last_update_error = Some(error.clone());
                            let _ = save_desktop_state(&state.desktop);
                        }
                        let message = user_facing_error(completion.operation, &error);
                        set_text(state.activity, &message);
                        if let Some(shell) = state.daily.as_ref() {
                            set_text(shell.home_failure, &message);
                        }
                    }
                }
            }
            Ok(BackgroundPayload::NodeSwitched(node_id)) => {
                state.desktop.profile_node_id = Some(node_id);
                let _ = save_desktop_state(&state.desktop);
                set_text(
                    state.activity,
                    "Active sing-box node switched and verified.",
                );
            }
            Ok(BackgroundPayload::DelayMeasured(value)) => {
                let (delay, url) = value.split_once('|').unwrap_or((&value, ""));
                set_text(state.profile_delay_status, delay);
                state.desktop.delay_test_url = (!url.is_empty()).then_some(url.to_string());
                let _ = save_desktop_state(&state.desktop);
                set_text(state.activity, "Selected node delay measured.");
            }
            Ok(BackgroundPayload::CoreChecked(status)) => {
                set_text(state.profile_runtime_status, &status);
                set_text(state.activity, "sing-box core selector is reachable.");
            }
            Ok(BackgroundPayload::DiagnosticReport(path)) => {
                match open_path(&path, "diagnostic report") {
                    Ok(()) => set_text(
                        state.activity,
                        &format!("Diagnostics opened: {}", path.display()),
                    ),
                    Err(error) => set_text(
                        state.activity,
                        &user_facing_error(OperationKind::Diagnostics, &error),
                    ),
                }
            }
            Ok(BackgroundPayload::StartupConfigured(enabled)) => {
                state.desktop.start_after_login = enabled;
                if let Some(shell) = state.daily.as_ref() {
                    SendMessageW(
                        shell.start_after_login,
                        BM_SETCHECK,
                        usize::from(enabled),
                        0,
                    );
                }
                if let Err(error) = save_desktop_state(&state.desktop) {
                    set_text(state.activity, &error);
                    return;
                }
                set_text(
                    state.activity,
                    if enabled {
                        "NetworkCore will start after this Windows user signs in."
                    } else {
                        "NetworkCore will not start automatically after sign-in."
                    },
                );
            }
            Err(error) => {
                if state.exit_after_disconnect {
                    state.exit_after_disconnect = false;
                }
                if matches!(completion.operation, OperationKind::SubscriptionUpdate) {
                    state.desktop.profile_last_update_error = Some(error.clone());
                    let _ = save_desktop_state(&state.desktop);
                }
                if completion.operation == OperationKind::Startup {
                    if let Some(shell) = state.daily.as_ref() {
                        SendMessageW(
                            shell.start_after_login,
                            BM_SETCHECK,
                            usize::from(state.desktop.start_after_login),
                            0,
                        );
                    }
                }
                let message = user_facing_error(completion.operation, &error);
                set_text(state.activity, &message);
                if let Some(shell) = state.daily.as_ref() {
                    set_text(shell.home_failure, &message);
                }
                let _ = append_managed_log("gui", &format!("background error: {error}"));
            }
        }
        refresh(state);
        state.last_runtime_refresh = Instant::now();
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
                let mut message = user_facing_error(OperationKind::Advanced, &error);
                if let Some(path) = report {
                    message.push_str(&format!(" Report: {}", path.display()));
                }
                if let Some(shell) = state.daily.as_ref() {
                    set_text(shell.home_failure, &message);
                }
                if state.desktop.debug_enabled {
                    let _ = append_managed_log("gui", &format!("diagnostics surfaced: {message}"));
                };
                set_text(state.activity, &message);
                refresh(state);
            }
        }
    }

    unsafe fn refresh(state: &mut AppState) {
        let runtime = read_runtime_status();
        state.runtime = runtime.clone();
        render_runtime_status(state, &runtime);
        if state.desktop.debug_enabled {
            let _ = append_managed_log("gui", &format!("debug: {}", runtime.status_line()));
        }
    }

    unsafe fn sync_startup_state(state: &mut AppState) -> Result<(), String> {
        let executable = env::current_exe().map_err(|error| error.to_string())?;
        let enabled =
            current_user_startup_enabled(&executable).map_err(|error| error.to_string())?;
        state.desktop.start_after_login = enabled;
        if let Some(shell) = state.daily.as_ref() {
            SendMessageW(
                shell.start_after_login,
                BM_SETCHECK,
                usize::from(enabled),
                0,
            );
        }
        Ok(())
    }

    unsafe fn render_runtime_status(state: &mut AppState, runtime: &WindowsRuntimeStatus) {
        if let Err(error) = restore_abandoned_owned_proxy(state, runtime) {
            let message = format!("NetworkCore proxy recovery failed: {error}");
            set_text(state.activity, &message);
            let _ = append_managed_log("gui", &message);
        }
        let service = match runtime.service_state {
            WindowsServiceState::NotInstalled => "Not installed".to_string(),
            WindowsServiceState::Stopped => "Stopped".to_string(),
            WindowsServiceState::StartPending => "Starting".to_string(),
            WindowsServiceState::Running => format!("Running (PID {})", runtime.service_process_id),
            WindowsServiceState::StopPending => "Stopping".to_string(),
            WindowsServiceState::Paused => "Paused".to_string(),
            WindowsServiceState::Unknown => runtime
                .service_detail
                .clone()
                .unwrap_or_else(|| "Unavailable".to_string()),
        };
        set_text(state.service_status, &service);
        let Some(shell) = state.daily.as_ref() else {
            return;
        };
        set_text(shell.status_summary, &runtime.status_line());
        set_text(
            shell.home_connection,
            home_page::connection_summary(runtime.connection),
        );
        set_text(shell.home_service, &service);
        set_text(shell.home_core, &runtime.sing_box.label());
        let proxy = home_page::proxy_summary(
            runtime.system_proxy_enabled,
            runtime.system_proxy_server.as_deref(),
            runtime.system_proxy_matches_managed,
        );
        set_text(shell.home_proxy, &proxy);

        let selected = selected_node_label(state);
        set_text(shell.home_node, &selected);
        self::tray::update(state.window, runtime.connection, &selected);
        let subscription = state
            .desktop
            .profile_source_url
            .clone()
            .or_else(|| {
                state
                    .desktop
                    .profile_source_path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "Not imported".to_string());
        set_text(shell.home_subscription, &subscription);
        let subscription_status = match (
            state.desktop.profile_last_successful_update.as_deref(),
            state.desktop.profile_last_update_error.as_deref(),
        ) {
            (_, Some(error)) => format!("Last update failed: {error}"),
            (Some(updated), None) => format!("Last successful import: {updated}"),
            (None, None) => "No successful import has been recorded.".to_string(),
        };
        set_text(shell.subscriptions_status, &subscription_status);
        let failure = runtime
            .configuration_error
            .as_deref()
            .or(runtime.last_error.as_deref())
            .or_else(|| {
                (runtime.connection == self::ui_state::ConnectionState::ConnectionFailed
                    && runtime.system_proxy_matches_managed == Some(false))
                .then_some("The current-user system proxy does not match the active profile.")
            })
            .unwrap_or("");
        set_text(shell.home_failure, failure);

        if connection_actions::should_auto_connect(
            state.desktop.auto_connect,
            state.auto_connect_attempted,
            runtime.connection.is_connected(),
        ) && state.pending_operation.is_none()
        {
            state.auto_connect_attempted = true;
            let _ = append_managed_log("gui", "automatic connection requested after startup");
            submit_service_start(state);
        }

        if connection_actions::should_restart_gui_started_core(
            state.desktop.auto_recover_core,
            state.core_recovery_attempted,
            state.gui_started_connection,
            runtime.connection,
        ) && state.pending_operation.is_none()
        {
            state.core_recovery_attempted = true;
            let _ = append_managed_log("gui", "one controlled core recovery was requested");
            submit_service_start(state);
        }
    }

    fn selected_node_label(state: &AppState) -> String {
        state
            .desktop
            .profile_node_id
            .as_deref()
            .and_then(|id| state.profile_node_catalog.iter().find(|node| node.id == id))
            .map(|node| format!("{} ({})", node.label, node.protocol))
            .or_else(|| state.desktop.profile_node_id.clone())
            .unwrap_or_else(|| "Not selected".to_string())
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

    fn validate_managed_configuration(path: &Path) -> Result<(), String> {
        let config = read_managed_config(path).map_err(|error| error.to_string())?;
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
        Ok(())
    }

    fn copy_diagnostic_summary(_state: &mut AppState) -> Result<(), String> {
        let runtime = read_runtime_status();
        let mut summary = format!(
            "AnixOps NetworkCore\n{}\nconnection_state={}\n",
            runtime.status_line(),
            runtime.connection.label()
        );
        if let Some(error) = runtime.configuration_error.or(runtime.last_error) {
            summary.push_str(&format!("last_error={error}\n"));
        }
        copy_unicode_text_to_clipboard(&summary)
    }

    fn copy_unicode_text_to_clipboard(text: &str) -> Result<(), String> {
        let mut encoded = text.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let bytes = encoded.len() * std::mem::size_of::<u16>();
        let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) };
        if memory.is_null() {
            return Err(last_error("Clipboard memory could not be allocated"));
        }
        let target = unsafe { GlobalLock(memory) } as *mut u16;
        if target.is_null() {
            unsafe {
                GlobalFree(memory);
            }
            return Err(last_error("Clipboard memory could not be locked"));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(encoded.as_ptr(), target, encoded.len());
            GlobalUnlock(memory);
        }
        if unsafe { OpenClipboard(null_mut()) } == 0 {
            unsafe {
                GlobalFree(memory);
            }
            return Err(last_error("Clipboard could not be opened"));
        }
        let copied = unsafe { EmptyClipboard() != 0 && !SetClipboardData(13, memory).is_null() };
        unsafe {
            CloseClipboard();
        }
        if !copied {
            unsafe {
                GlobalFree(memory);
            }
            return Err(last_error("Diagnostic summary could not be copied"));
        }
        encoded.clear();
        Ok(())
    }

    fn write_diagnostic_report(state: &mut AppState) -> Result<PathBuf, String> {
        let config_path = PathBuf::from(unsafe { get_text(state.config_path) });
        write_diagnostic_report_at(&config_path)
    }

    fn write_diagnostic_report_at(config_path: &Path) -> Result<PathBuf, String> {
        let mut report = String::from("AnixOps NetworkCore Windows diagnostics\n");
        report.push_str(&format!("managed_config_path={}\n", config_path.display()));

        match NativeWindowsSystemIntegration::new().service_status() {
            Ok(status) => report.push_str(&format!(
                "service_state={:?} service_process_id={}\n",
                status.state, status.process_id
            )),
            Err(error) => report.push_str(&format!("service_status_error={error}\n")),
        }

        let config = match read_managed_config(config_path) {
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
                "runtime_transition={} runtime_error={} sing_box_running={} sing_box_pid={} sing_box_exit_code={} native_mitm_running={} native_mitm_listener={} native_mitm_error={}\n",
                managed.last_transition,
                managed.last_error.unwrap_or_else(|| "none".to_string()),
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
        state
            .integration
            .start_service()
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    fn stop_service(state: &mut AppState) -> Result<(), String> {
        state
            .integration
            .stop_service()
            .map_err(|error| error.to_string())?;
        if state.desktop.proxy_snapshot.is_some() {
            restore_proxy(state)?;
        }
        Ok(())
    }

    fn apply_configuration(state: &mut AppState) -> Result<(), String> {
        let source = PathBuf::from(unsafe { get_text(state.config_path) });
        let mut config = read_managed_config(&source).map_err(|error| error.to_string())?;
        config.system_proxy_owner = if config
            .native_mitm
            .as_ref()
            .is_some_and(|native_mitm| native_mitm.enabled)
        {
            WindowsSystemProxyOwner::Service
        } else {
            WindowsSystemProxyOwner::Desktop
        };
        write_managed_config(&windows_managed_config_path(), &config)
            .map_err(|error| error.to_string())?;
        load_configuration_fields(state);
        Ok(())
    }

    fn import_profile_payload(state: &mut AppState, profile: ProfilePayload) -> Result<(), String> {
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
        let previous_sing_box_config = read_managed_sing_box_config_before_import()?;
        let imported = render_local_profile_config_from_payload(state, profile, listen_port, mode)?;
        managed.system_proxy = if native_mitm_enabled {
            Some(WindowsProxySettings {
                enabled: true,
                server: format!("127.0.0.1:{NATIVE_MITM_LISTEN_PORT}"),
                bypass: "<local>".to_string(),
            })
        } else {
            imported
                .local_http_proxy
                .clone()
                .map(|server| WindowsProxySettings {
                    enabled: true,
                    server,
                    bypass: "<local>".to_string(),
                })
        };
        managed.system_proxy_owner = if native_mitm_enabled {
            WindowsSystemProxyOwner::Service
        } else {
            WindowsSystemProxyOwner::Desktop
        };
        if native_mitm_enabled {
            if let Some(native_mitm) = managed.native_mitm.as_mut() {
                native_mitm.sing_box_config_snapshot_path =
                    imported.sing_box_config_snapshot_path.clone();
            }
        }
        managed.sing_box = Some(WindowsManagedSingBoxConfig {
            enabled: true,
            executable_path: imported.executable_path.clone(),
            config_path: imported.config_path.clone(),
            working_directory: Some(imported.config_parent.clone()),
            log_path: windows_managed_log_directory().join("sing-box.log"),
        });
        write_imported_profile_managed_config(
            &managed,
            &imported.config_path,
            previous_sing_box_config.as_deref(),
        )?;
        apply_imported_profile_desktop_state(state, &imported);
        state.desktop.profile_last_successful_update = Some(current_local_timestamp());
        state.desktop.profile_last_update_error = None;
        save_desktop_state(&state.desktop)?;
        load_configuration_fields(state);
        Ok(())
    }

    fn enable_https_mitm(state: &mut AppState) -> Result<(), String> {
        let restart = stop_running_service_for_reconfigure(state)?;
        let (certificate_path, private_key_path) = ensure_mitm_ca_material()?;
        let mut managed = managed_config_or_default()?;
        let previous_sing_box_config = read_managed_sing_box_config_before_import()?;
        let imported = render_local_profile_config(
            state,
            SING_BOX_MITM_UPSTREAM_PORT,
            ProfileRenderMode::NativeMitm,
        )?;
        managed.system_proxy = Some(WindowsProxySettings {
            enabled: true,
            server: format!("127.0.0.1:{NATIVE_MITM_LISTEN_PORT}"),
            bypass: "<local>".to_string(),
        });
        managed.system_proxy_owner = WindowsSystemProxyOwner::Service;
        managed.sing_box = Some(WindowsManagedSingBoxConfig {
            enabled: true,
            executable_path: imported.executable_path.clone(),
            config_path: imported.config_path.clone(),
            working_directory: Some(imported.config_parent.clone()),
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
            sing_box_config_snapshot_path: imported.sing_box_config_snapshot_path.clone(),
        });
        write_imported_profile_managed_config(
            &managed,
            &imported.config_path,
            previous_sing_box_config.as_deref(),
        )?;
        apply_imported_profile_desktop_state(state, &imported);
        save_desktop_state(&state.desktop)?;
        unsafe {
            set_text(
                state.certificate_path,
                certificate_path.to_string_lossy().as_ref(),
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
        managed.system_proxy_owner = WindowsSystemProxyOwner::Service;
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
        let location = unsafe { get_text(state.profile_source) };
        let location = location.trim();
        if location.is_empty() {
            return Err("Profile file path or subscription URL is required".to_string());
        }
        render_local_profile_config_from_payload(
            state,
            load_profile_payload(location)?,
            listen_port,
            mode,
        )
    }

    fn render_local_profile_config_from_payload(
        state: &mut AppState,
        ProfilePayload {
            payload,
            source_path,
            source_url,
        }: ProfilePayload,
        listen_port: u16,
        mode: ProfileRenderMode,
    ) -> Result<ImportedSingBoxProfile, String> {
        let executable_path = state
            .desktop
            .sing_box_executable_path
            .clone()
            .filter(|path| path.exists())
            .ok_or_else(|| "Install sing-box before importing a profile".to_string())?;
        let config_path = windows_managed_data_directory()
            .join("sing-box")
            .join("config.json");
        let config_parent = config_path
            .parent()
            .ok_or_else(|| "sing-box config path has no parent directory".to_string())?
            .to_path_buf();
        fs::create_dir_all(&config_parent).map_err(|error| error.to_string())?;

        if let Some(native_config) = inspect_sing_box_native_config(&payload) {
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
            return Ok(ImportedSingBoxProfile {
                executable_path,
                config_path,
                config_parent,
                local_http_proxy,
                sing_box_config_snapshot_path,
                source_path,
                source_url,
                selected_node_id: None,
                node_catalog: Vec::new(),
                config_sha256: None,
            });
        }

        let nodes = parse_profile_nodes(&payload)?;
        let selected_node_id = unsafe { selected_profile_node_id(state) };
        let source_options = profile_node_options(&nodes);
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
        let selectable_options =
            profile_node_options_from_selector(&rendered.selectable_nodes, &source_options)?;
        write_managed_text_atomic(&config_path, &rendered.json)
            .map_err(|error| error.to_string())?;

        Ok(ImportedSingBoxProfile {
            executable_path,
            config_path,
            config_parent,
            local_http_proxy: Some(format!("127.0.0.1:{listen_port}")),
            sing_box_config_snapshot_path: None,
            source_path,
            source_url,
            selected_node_id: Some(rendered.selected_node_id),
            node_catalog: selectable_options,
            config_sha256: Some(sing_box_config_sha256(&rendered.json)),
        })
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

    unsafe fn replace_profile_node_options_from_options(
        state: &mut AppState,
        profile_nodes: Vec<DesktopProfileNode>,
    ) {
        state.profile_node_catalog = profile_nodes;
        replace_profile_node_selector_items(state, state.profile_node_catalog.clone());
    }

    unsafe fn replace_profile_node_selector_items(
        state: &mut AppState,
        profile_nodes: Vec<DesktopProfileNode>,
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
        state.profile_node_catalog.clear();
        SendMessageW(state.profile_node_id, CB_RESETCONTENT, 0, 0);
        set_text(state.profile_node_id, "");
    }

    fn apply_imported_profile_desktop_state(
        state: &mut AppState,
        imported: &ImportedSingBoxProfile,
    ) {
        state.desktop.profile_source_path = imported.source_path.clone();
        state.desktop.profile_source_url = imported.source_url.clone();
        state.desktop.profile_node_id = imported.selected_node_id.clone();
        state.desktop.profile_node_catalog = imported.node_catalog.clone();
        state.desktop.profile_config_sha256 = imported.config_sha256.clone();
        unsafe {
            if imported.node_catalog.is_empty() {
                clear_profile_node_options(state);
            } else {
                replace_profile_node_options_from_options(state, imported.node_catalog.clone());
            }
        }
    }

    fn restore_saved_profile_node_catalog(state: &mut AppState) -> Result<bool, String> {
        let saved_nodes = state.desktop.profile_node_catalog.clone();
        let Some(expected_digest) = state.desktop.profile_config_sha256.clone() else {
            return Ok(false);
        };
        if saved_nodes.is_empty() {
            return Ok(false);
        }

        let managed_path = windows_managed_config_path();
        if !managed_path.exists() {
            return Ok(false);
        }
        let managed = read_managed_config(&managed_path).map_err(|error| {
            format!(
                "managed configuration could not be read from {}: {error}",
                managed_path.display()
            )
        })?;
        let Some(sing_box) = managed.sing_box.filter(|sing_box| sing_box.enabled) else {
            return Ok(false);
        };
        let content = fs::read_to_string(&sing_box.config_path).map_err(|error| {
            format!(
                "managed sing-box configuration could not be read from {}: {error}",
                sing_box.config_path.display()
            )
        })?;
        if sing_box_config_sha256(&content) != expected_digest {
            return Ok(false);
        }
        let Some(selector) = inspect_sing_box_local_selector_snapshot(&content) else {
            return Ok(false);
        };
        if !selector_tags_match_saved_catalog(&saved_nodes, &selector.outbound_tags) {
            return Ok(false);
        }

        unsafe {
            replace_profile_node_options_from_options(state, saved_nodes);
        }
        Ok(true)
    }

    fn selector_tags_match_saved_catalog(
        saved_nodes: &[DesktopProfileNode],
        selector_tags: &[String],
    ) -> bool {
        saved_nodes
            .iter()
            .map(|node| node.outbound_tag.as_str())
            .eq(selector_tags.iter().map(String::as_str))
    }

    unsafe fn selected_profile_node_id(state: &AppState) -> String {
        selected_profile_node_id_from_value(&state.profile_nodes, &get_text(state.profile_node_id))
    }

    fn profile_node_options(nodes: &[NodeDescriptor]) -> Vec<DesktopProfileNode> {
        nodes
            .iter()
            .enumerate()
            .map(|(index, node)| DesktopProfileNode {
                id: node.id.clone(),
                label: profile_node_label(node),
                protocol: format!("{:?}", node.protocol),
                outbound_tag: sing_box_local_selector_outbound_tag(index),
            })
            .collect()
    }

    fn profile_node_options_from_selector(
        nodes: &[SingBoxLocalProxySelectableNode],
        source_nodes: &[DesktopProfileNode],
    ) -> Result<Vec<DesktopProfileNode>, String> {
        nodes
            .iter()
            .map(|node| {
                let source = source_nodes
                    .iter()
                    .find(|source| source.id == node.id)
                    .ok_or_else(|| {
                        format!(
                            "Generated sing-box selector node {} was not present in the imported catalog",
                            node.id
                        )
                    })?;
                Ok(DesktopProfileNode {
                    id: node.id.clone(),
                    label: format!(
                        "{} [{}] ({})",
                        node.name.replace(['\r', '\n'], " "),
                        node.id,
                        source.protocol
                    ),
                    protocol: source.protocol.clone(),
                    outbound_tag: node.outbound_tag.clone(),
                })
            })
            .collect()
    }

    fn selected_profile_node_id_from_value(options: &[DesktopProfileNode], value: &str) -> String {
        options
            .iter()
            .find(|option| option.label == value)
            .map(|option| option.id.clone())
            .unwrap_or_else(|| value.to_string())
    }

    fn profile_node_label(node: &NodeDescriptor) -> String {
        let name = node.name.replace(['\r', '\n'], " ");
        format!("{name} [{}] ({:?})", node.id, node.protocol)
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

    fn read_managed_sing_box_config_before_import() -> Result<Option<String>, String> {
        let config_path = windows_managed_data_directory()
            .join("sing-box")
            .join("config.json");
        match fs::read_to_string(&config_path) {
            Ok(content) => Ok(Some(content)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!(
                "Existing managed sing-box configuration could not be read from {}: {error}",
                config_path.display()
            )),
        }
    }

    fn write_imported_profile_managed_config(
        managed: &WindowsManagedConfig,
        config_path: &Path,
        previous_config: Option<&str>,
    ) -> Result<(), String> {
        if let Err(error) = write_managed_config(&windows_managed_config_path(), managed) {
            let original_error = error.to_string();
            if let Err(rollback) = restore_imported_sing_box_config(config_path, previous_config) {
                return Err(format!(
                    "Managed configuration update failed: {original_error}; the imported sing-box configuration could not be rolled back: {rollback}"
                ));
            }
            let rollback_message = if previous_config.is_some() {
                "the prior sing-box configuration was restored"
            } else {
                "the newly written sing-box configuration was removed"
            };
            return Err(format!(
                "Managed configuration update failed and {rollback_message}: {original_error}"
            ));
        }
        Ok(())
    }

    fn restore_imported_sing_box_config(
        config_path: &Path,
        previous_config: Option<&str>,
    ) -> Result<(), String> {
        match previous_config {
            Some(content) => write_managed_text_atomic(config_path, content).map_err(|error| {
                format!(
                    "prior sing-box configuration could not be written to {}: {error}",
                    config_path.display()
                )
            }),
            None => {
                if let Err(error) = fs::remove_file(config_path) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        return Err(format!(
                            "new sing-box configuration could not be removed from {}: {error}",
                            config_path.display()
                        ));
                    }
                }
                Ok(())
            }
        }
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
            system_proxy_owner: WindowsSystemProxyOwner::Service,
            root_certificate_path: None,
            driver_package: None,
            tunnel: None,
            sing_box: None,
            native_mitm: None,
        })
    }

    fn restore_proxy(state: &mut AppState) -> Result<(), String> {
        let Some(snapshot) = state.desktop.proxy_snapshot.clone() else {
            return Err("no GUI-owned system proxy snapshot is available to restore".to_string());
        };
        let current = read_current_user_system_proxy().map_err(|error| error.to_string())?;
        if !owns_current_proxy(&state.desktop, &current) {
            clear_gui_proxy_ownership(state)?;
            return Err(
                "the current-user proxy no longer matches the GUI-applied settings; it was left unchanged"
                    .to_string(),
            );
        }
        state
            .integration
            .restore_system_proxy(&snapshot)
            .map_err(|error| error.to_string())?;
        clear_gui_proxy_ownership(state)?;
        Ok(())
    }

    fn clear_gui_proxy_ownership(state: &mut AppState) -> Result<(), String> {
        let snapshot = state.desktop.proxy_snapshot.take();
        let applied_proxy = state.desktop.applied_proxy.take();
        if let Err(error) = save_desktop_state(&state.desktop) {
            state.desktop.proxy_snapshot = snapshot;
            state.desktop.applied_proxy = applied_proxy;
            return Err(error);
        }
        Ok(())
    }

    fn restore_abandoned_owned_proxy(
        state: &mut AppState,
        runtime: &WindowsRuntimeStatus,
    ) -> Result<(), String> {
        if state.desktop.proxy_snapshot.is_none()
            || !matches!(
                runtime.service_state,
                WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
            )
            || !matches!(
                &runtime.sing_box,
                self::runtime_status::SingBoxProcessStatus::NotConfigured
                    | self::runtime_status::SingBoxProcessStatus::Exited { .. }
                    | self::runtime_status::SingBoxProcessStatus::Unavailable {
                        process_id: None,
                        ..
                    }
            )
        {
            return Ok(());
        }
        let current = read_current_user_system_proxy().map_err(|error| error.to_string())?;
        if !owns_current_proxy(&state.desktop, &current) {
            clear_gui_proxy_ownership(state)?;
            let _ = append_managed_log(
                "gui",
                "cleared stale GUI proxy ownership without changing the current-user proxy",
            );
            return Ok(());
        }
        restore_proxy(state)?;
        let _ = append_managed_log(
            "gui",
            "restored the GUI-owned current-user proxy after an interrupted runtime",
        );
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

    fn current_local_timestamp() -> String {
        let mut local_time: SYSTEMTIME = unsafe { zeroed() };
        unsafe {
            GetLocalTime(&mut local_time);
        }
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            local_time.wYear,
            local_time.wMonth,
            local_time.wDay,
            local_time.wHour,
            local_time.wMinute,
            local_time.wSecond
        )
    }

    fn request_elevation(debug: bool, start_after_login: bool) -> Result<bool, String> {
        let title = wide(APP_TITLE);
        let message = wide(
            "NetworkCore needs administrator permission to manage the Windows service and its managed configuration. Current-user proxy settings are applied only after the core is ready. Select OK to continue.",
        );
        let accepted = unsafe {
            MessageBoxW(
                null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OKCANCEL | MB_ICONINFORMATION,
            )
        } == IDOK;
        if !accepted {
            return Ok(false);
        }
        elevate(debug, start_after_login)?;
        Ok(true)
    }

    fn elevate(debug: bool, start_after_login: bool) -> Result<(), String> {
        let executable = env::current_exe().map_err(|error| error.to_string())?;
        let executable = wide_os(&executable);
        let verb = wide("runas");
        let arguments = wide(elevation_arguments(debug, start_after_login));
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

    const fn elevation_arguments(debug: bool, start_after_login: bool) -> &'static str {
        match (debug, start_after_login) {
            (true, true) => "--debug --start-after-login",
            (true, false) => "--debug",
            (false, true) => "--start-after-login",
            (false, false) => "",
        }
    }

    #[cfg(test)]
    #[test]
    fn elevation_keeps_the_login_startup_argument() {
        assert_eq!(elevation_arguments(false, true), "--start-after-login");
        assert_eq!(
            elevation_arguments(true, true),
            "--debug --start-after-login"
        );
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

            assert_eq!(
                options[0].label,
                "Primary node [primary-node] (Shadowsocks)"
            );
            assert_eq!(options[0].outbound_tag, "networkcore-node-0");
            assert_eq!(
                selected_profile_node_id_from_value(&options, &options[0].label),
                "primary-node"
            );
            assert_eq!(
                selected_profile_node_id_from_value(&options, "manual-node-id"),
                "manual-node-id"
            );
        }

        #[test]
        fn saved_catalog_requires_the_generated_selector_tag_order() {
            let saved = vec![
                DesktopProfileNode {
                    id: "primary-node".to_string(),
                    label: "Primary".to_string(),
                    protocol: "Shadowsocks".to_string(),
                    outbound_tag: "networkcore-node-0".to_string(),
                },
                DesktopProfileNode {
                    id: "backup-node".to_string(),
                    label: "Backup".to_string(),
                    protocol: "Shadowsocks".to_string(),
                    outbound_tag: "networkcore-node-1".to_string(),
                },
            ];
            assert!(selector_tags_match_saved_catalog(
                &saved,
                &[
                    "networkcore-node-0".to_string(),
                    "networkcore-node-1".to_string()
                ]
            ));
            assert!(!selector_tags_match_saved_catalog(
                &saved,
                &[
                    "networkcore-node-1".to_string(),
                    "networkcore-node-0".to_string()
                ]
            ));
        }

        #[test]
        fn failed_profile_update_restores_the_prior_generated_config() {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "networkcore-windows-gui-profile-rollback-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&directory).expect("test directory should be created");
            let config_path = directory.join("config.json");
            fs::write(&config_path, "previous generated configuration")
                .expect("prior config should be written");
            fs::write(&config_path, "failed replacement")
                .expect("replacement config should be written");

            restore_imported_sing_box_config(
                &config_path,
                Some("previous generated configuration"),
            )
            .expect("prior config should be restored");

            assert_eq!(
                fs::read_to_string(&config_path).expect("restored config should be readable"),
                "previous generated configuration"
            );
            fs::remove_dir_all(&directory).expect("test directory should be removed");
        }
    }
}
