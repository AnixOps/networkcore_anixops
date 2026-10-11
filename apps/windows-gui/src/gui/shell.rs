use super::pages::{home as home_page, settings as settings_page};
use super::startup::DesktopState;
use super::widgets::{button, checkbox, control, edit, group, label, selector, wide};
use super::{
    ID_APPLY_CONFIG, ID_AUTO_CONNECT, ID_AUTO_RECOVER_CORE, ID_CHECK_PROFILE_RUNTIME, ID_CONNECT,
    ID_COPY_DIAGNOSTICS, ID_DISABLE_HTTPS_MITM, ID_DISCONNECT, ID_ENABLE_HTTPS_MITM,
    ID_FILTER_PROFILE_NODES, ID_IMPORT_PROFILE, ID_INSTALL_CERTIFICATE, ID_INSTALL_DRIVER,
    ID_INSTALL_SERVICE, ID_INSTALL_SING_BOX, ID_LOAD_PROFILE_NODES, ID_NAV_ADVANCED,
    ID_NAV_DIAGNOSTICS, ID_NAV_HOME, ID_NAV_NODES, ID_NAV_SETTINGS, ID_NAV_SUBSCRIPTIONS,
    ID_OPEN_CORE_LOG, ID_OPEN_LOGS, ID_OPEN_MANAGED_CONFIG, ID_REFRESH, ID_REMOVE_CERTIFICATE,
    ID_REMOVE_DRIVER, ID_RESTART_SERVICE, ID_RESTORE_PROXY, ID_SHOW_DIAGNOSTICS,
    ID_START_AFTER_LOGIN, ID_SWITCH_PROFILE_NODE, ID_TEST_PROFILE_NODE_DELAY, ID_TOGGLE_DEBUG,
    ID_TOGGLE_THEME, ID_UPDATE_PROFILE, ID_VALIDATE_CONFIGURATION,
};
use engine_singbox::DEFAULT_SING_BOX_CLASH_API_DELAY_TEST_URL;
use platform_windows::managed::{windows_managed_config_path, windows_managed_log_directory};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{HINSTANCE, HWND};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    SendMessageW, CB_ADDSTRING, CB_SETCURSEL, WS_BORDER, WS_CHILD, WS_VISIBLE,
};

pub(super) struct PagePanels {
    pub(super) home: HWND,
    pub(super) nodes: HWND,
    pub(super) subscriptions: HWND,
    pub(super) settings: HWND,
    pub(super) diagnostics: HWND,
    pub(super) advanced: HWND,
}

pub(super) struct DailyShell {
    pub(super) panels: PagePanels,
    pub(super) page_title: HWND,
    pub(super) status_summary: HWND,
    pub(super) theme_button: HWND,
    pub(super) home_connection: HWND,
    pub(super) home_node: HWND,
    pub(super) home_subscription: HWND,
    pub(super) home_core: HWND,
    pub(super) home_service: HWND,
    pub(super) home_proxy: HWND,
    pub(super) home_failure: HWND,
    pub(super) subscriptions_status: HWND,
    pub(super) nodes_search: HWND,
    pub(super) nodes_protocol_filter: HWND,
    pub(super) config_path: HWND,
    pub(super) profile_source: HWND,
    pub(super) profile_node_id: HWND,
    pub(super) delay_test_url: HWND,
    pub(super) profile_delay_status: HWND,
    pub(super) profile_runtime_status: HWND,
    pub(super) start_after_login: HWND,
    pub(super) auto_connect: HWND,
    pub(super) auto_recover_core: HWND,
    pub(super) activity: HWND,
    pub(super) debug_status: HWND,
    pub(super) certificate_path: HWND,
    pub(super) driver_path: HWND,
}

pub(super) unsafe fn create(
    window: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    desktop: &DesktopState,
) -> DailyShell {
    group(window, instance, font, "", 14, 14, 190, 740);
    label(window, instance, font, "ANIXOPS", 32, 36, 150, 20);
    label(window, instance, font, "NetworkCore", 32, 58, 150, 26);
    label(
        window,
        instance,
        font,
        "Windows proxy client",
        32,
        86,
        150,
        20,
    );
    button(
        window,
        instance,
        font,
        "Home",
        ID_NAV_HOME,
        28,
        126,
        160,
        34,
    );
    button(
        window,
        instance,
        font,
        "Nodes",
        ID_NAV_NODES,
        28,
        170,
        160,
        34,
    );
    button(
        window,
        instance,
        font,
        "Subscriptions",
        ID_NAV_SUBSCRIPTIONS,
        28,
        214,
        160,
        34,
    );
    button(
        window,
        instance,
        font,
        "Settings",
        ID_NAV_SETTINGS,
        28,
        258,
        160,
        34,
    );
    button(
        window,
        instance,
        font,
        "Diagnostics",
        ID_NAV_DIAGNOSTICS,
        28,
        302,
        160,
        34,
    );
    button(
        window,
        instance,
        font,
        "Advanced",
        ID_NAV_ADVANCED,
        28,
        346,
        160,
        34,
    );
    let theme_button = button(
        window,
        instance,
        font,
        if desktop.dark_theme {
            "Use light mode"
        } else {
            "Use dark mode"
        },
        ID_TOGGLE_THEME,
        28,
        688,
        160,
        32,
    );

    let page_title = label(window, instance, font, "Home", 228, 22, 550, 28);
    let status_summary = label(
        window,
        instance,
        font,
        "Reading Windows runtime status...",
        228,
        52,
        900,
        22,
    );
    let panels = PagePanels {
        home: page_panel(window, instance, 220, 88),
        nodes: page_panel(window, instance, 220, 88),
        subscriptions: page_panel(window, instance, 220, 88),
        settings: page_panel(window, instance, 220, 88),
        diagnostics: page_panel(window, instance, 220, 88),
        advanced: page_panel(window, instance, 220, 88),
    };

    let home = home_page::create(
        panels.home,
        instance,
        font,
        label,
        group,
        button,
        home_page::CommandIds {
            connect: ID_CONNECT,
            disconnect: ID_DISCONNECT,
            refresh: ID_REFRESH,
            restore_proxy: ID_RESTORE_PROXY,
        },
    );
    let nodes = create_nodes_page(panels.nodes, instance, font, desktop);
    let subscriptions = create_subscriptions_page(panels.subscriptions, instance, font, desktop);

    let managed_config_path = windows_managed_config_path();
    let settings = settings_page::create(
        panels.settings,
        instance,
        font,
        label,
        group,
        button,
        edit,
        checkbox,
        settings_page::CommandIds {
            open_config: ID_OPEN_MANAGED_CONFIG,
            validate_config: ID_VALIDATE_CONFIGURATION,
            apply_config: ID_APPLY_CONFIG,
            install_core: ID_INSTALL_SING_BOX,
            start_after_login: ID_START_AFTER_LOGIN,
            auto_connect: ID_AUTO_CONNECT,
            auto_recover_core: ID_AUTO_RECOVER_CORE,
            restore_proxy: ID_RESTORE_PROXY,
        },
        settings_page::InitialValues {
            config_path: managed_config_path.to_string_lossy().as_ref(),
            start_after_login: desktop.start_after_login,
            auto_connect: desktop.auto_connect,
            auto_recover_core: desktop.auto_recover_core,
        },
    );
    let diagnostics = create_diagnostics_page(panels.diagnostics, instance, font);
    let advanced = create_advanced_page(panels.advanced, instance, font);

    DailyShell {
        panels,
        page_title,
        status_summary,
        theme_button,
        home_connection: home.connection,
        home_node: home.node,
        home_subscription: home.subscription,
        home_core: home.core,
        home_service: home.service,
        home_proxy: home.proxy,
        home_failure: home.failure,
        subscriptions_status: subscriptions.status,
        nodes_search: nodes.search,
        nodes_protocol_filter: nodes.protocol_filter,
        config_path: settings.config_path,
        profile_source: subscriptions.source,
        profile_node_id: nodes.selected_id,
        delay_test_url: nodes.delay_test_url,
        profile_delay_status: nodes.delay_status,
        profile_runtime_status: nodes.runtime_status,
        start_after_login: settings.start_after_login,
        auto_connect: settings.auto_connect,
        auto_recover_core: settings.auto_recover_core,
        activity: diagnostics.activity,
        debug_status: diagnostics.debug_status,
        certificate_path: advanced.certificate_path,
        driver_path: advanced.driver_path,
    }
}

unsafe fn page_panel(parent: HWND, instance: HINSTANCE, x: i32, y: i32) -> HWND {
    control(
        parent,
        instance,
        "STATIC",
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        0,
        x,
        y,
        900,
        620,
        0,
    )
}

struct NodeControls {
    search: HWND,
    protocol_filter: HWND,
    selected_id: HWND,
    delay_test_url: HWND,
    delay_status: HWND,
    runtime_status: HWND,
}

unsafe fn create_nodes_page(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    desktop: &DesktopState,
) -> NodeControls {
    label(parent, instance, font, "Nodes", 24, 20, 300, 26);
    label(
        parent,
        instance,
        font,
        "Only imported NodeCatalog profiles expose runtime selector controls. Native sing-box JSON remains pass-through.",
        24,
        50,
        850,
        36,
    );
    label(parent, instance, font, "Search", 24, 110, 80, 22);
    let search = edit(parent, instance, font, "", 106, 106, 290, 28);
    label(parent, instance, font, "Protocol", 414, 110, 80, 22);
    let protocol_filter = selector(parent, instance, font, "All", 488, 106, 180, 28);
    for value in [
        "All",
        "Shadowsocks",
        "Trojan",
        "VLESS",
        "VMess",
        "Hysteria2",
        "TUIC",
    ] {
        let value = wide(value);
        SendMessageW(protocol_filter, CB_ADDSTRING, 0, value.as_ptr() as isize);
    }
    SendMessageW(protocol_filter, CB_SETCURSEL, 0, 0);
    button(
        parent,
        instance,
        font,
        "Filter",
        ID_FILTER_PROFILE_NODES,
        684,
        106,
        100,
        30,
    );
    label(parent, instance, font, "Selected node", 24, 162, 110, 22);
    let selected_id = selector(parent, instance, font, "", 140, 158, 540, 28);
    button(
        parent,
        instance,
        font,
        "Switch active",
        ID_SWITCH_PROFILE_NODE,
        694,
        158,
        150,
        30,
    );
    label(parent, instance, font, "Delay URL", 24, 214, 100, 22);
    let delay_test_url = edit(
        parent,
        instance,
        font,
        desktop
            .delay_test_url
            .as_deref()
            .unwrap_or(DEFAULT_SING_BOX_CLASH_API_DELAY_TEST_URL),
        140,
        210,
        440,
        28,
    );
    button(
        parent,
        instance,
        font,
        "Test delay",
        ID_TEST_PROFILE_NODE_DELAY,
        594,
        210,
        120,
        30,
    );
    let delay_status = label(parent, instance, font, "Not tested", 730, 214, 130, 22);
    button(
        parent,
        instance,
        font,
        "Check core",
        ID_CHECK_PROFILE_RUNTIME,
        24,
        266,
        120,
        30,
    );
    let runtime_status = label(
        parent,
        instance,
        font,
        "Core has not been checked",
        160,
        270,
        690,
        22,
    );
    NodeControls {
        search,
        protocol_filter,
        selected_id,
        delay_test_url,
        delay_status,
        runtime_status,
    }
}

struct SubscriptionControls {
    source: HWND,
    status: HWND,
}

unsafe fn create_subscriptions_page(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    desktop: &DesktopState,
) -> SubscriptionControls {
    label(parent, instance, font, "Subscription", 24, 20, 300, 26);
    label(
        parent,
        instance,
        font,
        "Import a local profile or explicitly update one HTTP(S) URL. Failed updates keep the current working profile.",
        24,
        50,
        850,
        36,
    );
    label(parent, instance, font, "Profile / URL", 24, 110, 100, 22);
    let source_text = desktop
        .profile_source_url
        .clone()
        .or_else(|| {
            desktop
                .profile_source_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let source = edit(parent, instance, font, &source_text, 132, 106, 620, 28);
    button(
        parent,
        instance,
        font,
        "Load nodes",
        ID_LOAD_PROFILE_NODES,
        24,
        160,
        130,
        32,
    );
    button(
        parent,
        instance,
        font,
        "Import profile",
        ID_IMPORT_PROFILE,
        166,
        160,
        140,
        32,
    );
    button(
        parent,
        instance,
        font,
        "Update saved URL",
        ID_UPDATE_PROFILE,
        318,
        160,
        160,
        32,
    );
    let status = label(
        parent,
        instance,
        font,
        "No subscription has been imported.",
        24,
        216,
        830,
        46,
    );
    group(
        parent,
        instance,
        font,
        "Supported import formats",
        20,
        290,
        860,
        126,
    );
    label(
        parent,
        instance,
        font,
        "Shadowsocks, Trojan, VLESS, VMess, Hysteria2, TUIC, supported Clash/Sing-box/Surge/Loon/Quantumult X catalogs, and native sing-box JSON.",
        40,
        324,
        810,
        42,
    );
    label(
        parent,
        instance,
        font,
        "Scheduled refresh, subscription groups, route/rule fetching, and automatic node selection are not available.",
        40,
        374,
        810,
        22,
    );
    SubscriptionControls { source, status }
}

struct DiagnosticsControls {
    activity: HWND,
    debug_status: HWND,
}

unsafe fn create_diagnostics_page(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
) -> DiagnosticsControls {
    label(
        parent,
        instance,
        font,
        "Logs and diagnostics",
        24,
        20,
        320,
        26,
    );
    let activity = label(parent, instance, font, "Ready", 24, 60, 840, 42);
    button(
        parent,
        instance,
        font,
        "Open log folder",
        ID_OPEN_LOGS,
        24,
        122,
        150,
        32,
    );
    button(
        parent,
        instance,
        font,
        "Open core log",
        ID_OPEN_CORE_LOG,
        186,
        122,
        140,
        32,
    );
    button(
        parent,
        instance,
        font,
        "Create report",
        ID_SHOW_DIAGNOSTICS,
        338,
        122,
        140,
        32,
    );
    button(
        parent,
        instance,
        font,
        "Copy summary",
        ID_COPY_DIAGNOSTICS,
        490,
        122,
        140,
        32,
    );
    label(
        parent,
        instance,
        font,
        "Reports include GUI, service, sing-box, and native MITM log tails, configuration preflight facts, SCM state, and the last managed runtime error.",
        24,
        182,
        830,
        42,
    );
    let debug_status = label(
        parent,
        instance,
        font,
        "Debug logging: disabled",
        24,
        246,
        320,
        22,
    );
    button(
        parent,
        instance,
        font,
        "Toggle GUI debug",
        ID_TOGGLE_DEBUG,
        356,
        242,
        150,
        30,
    );
    label(
        parent,
        instance,
        font,
        &format!(
            "Log directory: {}",
            windows_managed_log_directory().display()
        ),
        24,
        294,
        830,
        22,
    );
    DiagnosticsControls {
        activity,
        debug_status,
    }
}

struct AdvancedControls {
    certificate_path: HWND,
    driver_path: HWND,
}

unsafe fn create_advanced_page(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
) -> AdvancedControls {
    label(
        parent,
        instance,
        font,
        "Advanced and experimental",
        24,
        20,
        400,
        26,
    );
    label(
        parent,
        instance,
        font,
        "These actions change certificates, driver state, or the local HTTPS interception path. Review diagnostics and use only when you understand the effect.",
        24,
        50,
        830,
        42,
    );
    group(
        parent,
        instance,
        font,
        "HTTPS MITM (explicit HTTP/1.1 only)",
        20,
        112,
        860,
        94,
    );
    button(
        parent,
        instance,
        font,
        "Enable HTTPS MITM",
        ID_ENABLE_HTTPS_MITM,
        40,
        152,
        180,
        32,
    );
    button(
        parent,
        instance,
        font,
        "Disable HTTPS MITM",
        ID_DISABLE_HTTPS_MITM,
        232,
        152,
        180,
        32,
    );
    group(
        parent,
        instance,
        font,
        "Certificate and driver lifecycle",
        20,
        228,
        860,
        178,
    );
    label(parent, instance, font, "Root CA", 40, 262, 80, 22);
    let certificate_path = edit(parent, instance, font, "", 124, 258, 520, 28);
    button(
        parent,
        instance,
        font,
        "Install CA",
        ID_INSTALL_CERTIFICATE,
        658,
        258,
        94,
        30,
    );
    button(
        parent,
        instance,
        font,
        "Remove CA",
        ID_REMOVE_CERTIFICATE,
        762,
        258,
        94,
        30,
    );
    label(parent, instance, font, "Driver INF", 40, 314, 80, 22);
    let driver_path = edit(parent, instance, font, "", 124, 310, 520, 28);
    button(
        parent,
        instance,
        font,
        "Install driver",
        ID_INSTALL_DRIVER,
        658,
        310,
        94,
        30,
    );
    button(
        parent,
        instance,
        font,
        "Remove driver",
        ID_REMOVE_DRIVER,
        762,
        310,
        94,
        30,
    );
    button(
        parent,
        instance,
        font,
        "Install service",
        ID_INSTALL_SERVICE,
        40,
        362,
        140,
        30,
    );
    button(
        parent,
        instance,
        font,
        "Restart service",
        ID_RESTART_SERVICE,
        192,
        362,
        140,
        30,
    );
    AdvancedControls {
        certificate_path,
        driver_path,
    }
}
