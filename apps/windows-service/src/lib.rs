//! Managed Windows runtime shared by the SCM entrypoint and contract tests.

use control_domain::{
    ConfigSnapshot, DomainError, DomainResult, Endpoint, GrantedPermissions, ListenerBind,
    ListenerDescriptor, ListenerKind, ListenerNetwork, ListenerRoute, MitmPluginService,
    NodeDescriptor, Protocol, ProxyEngineConfig, ProxyEngineLifecycleState, ProxyEngineService,
    RouteAction, RuleSet, SchemaVersion,
};
use engine_native::{
    NativeHttpMitmPluginHook, NativeProxyEngineService, NativeTlsMitmCaMaterial,
    DEFAULT_NATIVE_ENGINE_ID,
};
use engine_singbox::{
    SingBoxManagedProcessRequest, SingBoxManagedProcessState, SingBoxManagedProcessSupervisor,
};
use mitm_policy::{builtin_ad_block_plugin_package, AnixOpsMitmPluginService};
use networkcore_windows::{
    parse_args, OutputFormat, WindowsCliCommand, WindowsTunnelCommandService,
    WindowsTunnelPrepareStorageArgs, WindowsTunnelStatusArgs,
};
use platform_windows::managed::{
    read_managed_config, read_managed_state, write_managed_state, WindowsManagedConfig,
    WindowsManagedNativeMitmConfig, WindowsManagedState,
};
use platform_windows::system_integration::WindowsSystemIntegration;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const WINDOWS_MANAGED_RUNTIME_FAILED_CODE: &str = "windows.managed.runtime_failed";

pub struct WindowsManagedRuntime<I, T> {
    integration: I,
    tunnel: T,
    sing_box: SingBoxManagedProcessSupervisor,
    native_mitm: Option<NativeProxyEngineService>,
    config_path: PathBuf,
    state_path: PathBuf,
}

impl<I, T> WindowsManagedRuntime<I, T>
where
    I: WindowsSystemIntegration,
    T: WindowsTunnelCommandService,
{
    pub fn new(integration: I, tunnel: T, config_path: PathBuf, state_path: PathBuf) -> Self {
        Self {
            integration,
            tunnel,
            sing_box: SingBoxManagedProcessSupervisor::default(),
            native_mitm: None,
            config_path,
            state_path,
        }
    }

    pub fn start(&mut self) -> DomainResult<WindowsManagedState> {
        let config = read_managed_config(&self.config_path)?;
        let mut state = self.read_state_or_default()?;
        let previous = state.clone();
        state.last_transition = "starting".to_string();
        state.last_error = None;
        self.persist(&state)?;

        let result = self.apply_configuration(&config, &mut state);
        match result {
            Ok(()) => {
                state.last_transition = "running".to_string();
                state.last_error = None;
                self.persist(&state)?;
                Ok(state)
            }
            Err(error) => {
                self.rollback_start(&mut state, &previous);
                state.last_transition = "failed".to_string();
                state.last_error = Some(error.message.clone());
                let _ = self.persist(&state);
                Err(error)
            }
        }
    }

    pub fn stop(&mut self) -> DomainResult<WindowsManagedState> {
        let config = read_managed_config(&self.config_path)?;
        let mut state = self.read_state_or_default()?;
        state.last_transition = "stopping".to_string();
        state.last_error = None;
        self.persist(&state)?;

        self.stop_native_mitm(&mut state, config.native_mitm.as_ref())?;
        self.stop_sing_box(
            &mut state,
            config
                .sing_box
                .as_ref()
                .map(|sing_box| sing_box.log_path.clone()),
        )?;

        if state.tunnel_running {
            if let Some(tunnel) = &config.tunnel {
                let command = parse_managed_command(tunnel.stop_arguments())?;
                match command {
                    WindowsCliCommand::TunnelStop(args) => {
                        self.tunnel.stop(&args)?;
                    }
                    _ => return Err(runtime_error("managed stop command is invalid")),
                }
            }
            state.tunnel_running = false;
            self.persist(&state)?;
        }

        if let Some(snapshot) = state.proxy_snapshot.take() {
            self.integration.restore_system_proxy(&snapshot)?;
            self.persist(&state)?;
        }

        state.last_transition = "stopped".to_string();
        self.persist(&state)?;
        Ok(state)
    }

    /// Polls the long-lived components that the Windows service owns.
    ///
    /// sing-box has no SCM process relationship, so a child exit would otherwise
    /// leave the service marked Running and a managed system proxy pointing at a
    /// dead loopback listener. This method records a durable failure before the
    /// host asks `stop_after_runtime_failure` to roll back runtime resources.
    pub fn poll_health(&mut self) -> DomainResult<()> {
        let config = read_managed_config(&self.config_path)?;
        let mut state = self.read_state_or_default()?;
        let previous = state.clone();

        if config
            .sing_box
            .as_ref()
            .is_some_and(|sing_box| sing_box.enabled)
        {
            let status = self.sing_box.status()?;
            state.sing_box_running = status.state == SingBoxManagedProcessState::Running;
            state.sing_box_process_id = status.process_id;
            state.sing_box_exit_code = status.exit_code;

            if status.state != SingBoxManagedProcessState::Running {
                return self.record_runtime_failure(
                    &mut state,
                    format!(
                        "managed sing-box process exited unexpectedly state={:?} exit_code={:?}",
                        status.state, status.exit_code
                    ),
                );
            }
        }

        if config
            .native_mitm
            .as_ref()
            .is_some_and(|native_mitm| native_mitm.enabled)
        {
            let status = match self.native_mitm.as_ref() {
                Some(service) => service.status(DEFAULT_NATIVE_ENGINE_ID)?,
                None => {
                    state.native_mitm_running = false;
                    state.native_mitm_listener = None;
                    return self.record_runtime_failure(
                        &mut state,
                        "managed native HTTPS MITM runtime is unavailable".to_string(),
                    );
                }
            };
            state.native_mitm_running = status.state == ProxyEngineLifecycleState::Running;
            if status.state != ProxyEngineLifecycleState::Running {
                state.native_mitm_listener = None;
                return self.record_runtime_failure(
                    &mut state,
                    format!(
                        "managed native HTTPS MITM runtime exited unexpectedly state={:?}",
                        status.state
                    ),
                );
            }
        }

        if state != previous {
            self.persist(&state)?;
        }
        Ok(())
    }

    /// Stops runtime resources after a health poll failure while keeping a
    /// machine-readable failed transition and its original cause on disk.
    pub fn stop_after_runtime_failure(
        &mut self,
        failure: &DomainError,
    ) -> DomainResult<WindowsManagedState> {
        match self.stop() {
            Ok(mut state) => {
                state.last_transition = "failed".to_string();
                state.last_error = Some(failure.message.clone());
                self.persist(&state)?;
                Ok(state)
            }
            Err(cleanup_error) => {
                let mut state = self.read_state_or_default()?;
                state.last_transition = "failed".to_string();
                state.last_error = Some(format!(
                    "{}; runtime rollback failed: {}",
                    failure.message, cleanup_error.message
                ));
                self.persist(&state)?;
                Err(DomainError::new(
                    WINDOWS_MANAGED_RUNTIME_FAILED_CODE,
                    state.last_error.clone().unwrap_or_default(),
                ))
            }
        }
    }

    pub fn purge(&mut self) -> DomainResult<WindowsManagedState> {
        let mut state = self.stop()?;
        if let Some(thumbprint) = state.certificate_sha1.take() {
            self.integration.remove_root_certificate(&thumbprint)?;
            self.persist(&state)?;
        }
        if let Some(thumbprint) = state.native_mitm_certificate_sha1.take() {
            self.integration.remove_root_certificate(&thumbprint)?;
            self.persist(&state)?;
        }
        if let Some(inf_path) = state.driver_inf_path.take() {
            state.driver_reboot_required = self.integration.uninstall_driver(&inf_path)?;
            self.persist(&state)?;
        }
        state.last_transition = "purged".to_string();
        self.persist(&state)?;
        Ok(state)
    }

    pub fn current_state(&self) -> DomainResult<WindowsManagedState> {
        self.read_state_or_default()
    }

    fn record_runtime_failure(
        &self,
        state: &mut WindowsManagedState,
        message: String,
    ) -> DomainResult<()> {
        state.last_transition = "failed".to_string();
        state.last_error = Some(message.clone());
        self.persist(state)?;
        Err(DomainError::new(
            WINDOWS_MANAGED_RUNTIME_FAILED_CODE,
            message,
        ))
    }

    fn apply_configuration(
        &mut self,
        config: &WindowsManagedConfig,
        state: &mut WindowsManagedState,
    ) -> DomainResult<()> {
        if state.driver_inf_path.is_none() {
            if let Some(driver) = &config.driver_package {
                let installed = self.integration.install_driver(&driver.inf_path)?;
                state.driver_inf_path = Some(installed.inf_path);
                state.driver_reboot_required = installed.reboot_required;
                self.persist(state)?;
            }
        }

        if state.certificate_sha1.is_none() {
            if let Some(certificate) = &config.root_certificate_path {
                state.certificate_sha1 =
                    Some(self.integration.install_root_certificate(certificate)?);
                self.persist(state)?;
            }
        }

        if config
            .sing_box
            .as_ref()
            .map(|sing_box| !sing_box.enabled)
            .unwrap_or(true)
            && state.sing_box_running
        {
            self.stop_sing_box(state, None)?;
        }

        if config
            .native_mitm
            .as_ref()
            .map(|native_mitm| !native_mitm.enabled)
            .unwrap_or(true)
            && state.native_mitm_running
        {
            self.stop_native_mitm(state, config.native_mitm.as_ref())?;
        }

        if let Some(sing_box) = &config.sing_box {
            if sing_box.enabled {
                let current_status = self.sing_box.status()?;
                let status = if current_status.state == SingBoxManagedProcessState::Running {
                    current_status
                } else {
                    self.sing_box.start(&SingBoxManagedProcessRequest {
                        executable_path: sing_box.executable_path.clone(),
                        config_path: sing_box.config_path.clone(),
                        working_directory: sing_box.working_directory.clone(),
                        log_path: sing_box.log_path.clone(),
                    })?
                };
                state.sing_box_running = status.state == SingBoxManagedProcessState::Running;
                state.sing_box_process_id = status.process_id;
                state.sing_box_exit_code = status.exit_code;
                state.sing_box_log_path = Some(sing_box.log_path.clone());
                self.persist(state)?;
            }
        }

        if let Some(native_mitm) = &config.native_mitm {
            if native_mitm.enabled {
                self.start_native_mitm(native_mitm, state)?;
            }
        }

        if config.system_proxy_owner.is_service_managed() && state.proxy_snapshot.is_none() {
            if let Some(proxy) = &config.system_proxy {
                state.proxy_snapshot = Some(self.integration.apply_system_proxy(proxy)?);
                self.persist(state)?;
            }
        }

        if let Some(tunnel) = &config.tunnel {
            if state.tunnel_running {
                let status = WindowsTunnelStatusArgs {
                    state_path: tunnel.state_path.clone(),
                    format: OutputFormat::Json,
                };
                if self.tunnel.status(&status).is_err() {
                    state.tunnel_running = false;
                    self.persist(state)?;
                }
            }

            if !state.tunnel_running {
                self.tunnel
                    .prepare_storage(&WindowsTunnelPrepareStorageArgs {
                        confirm: true,
                        format: OutputFormat::Json,
                    })?;
                let command = parse_managed_command(tunnel.start_arguments())?;
                match command {
                    WindowsCliCommand::TunnelStart(args) => {
                        self.tunnel.start(&args)?;
                    }
                    _ => return Err(runtime_error("managed start command is invalid")),
                }
                state.tunnel_running = true;
                self.persist(state)?;
            }
        }

        Ok(())
    }

    fn stop_sing_box(
        &mut self,
        state: &mut WindowsManagedState,
        configured_log_path: Option<PathBuf>,
    ) -> DomainResult<()> {
        if !state.sing_box_running {
            return Ok(());
        }
        let log_path = configured_log_path
            .or_else(|| state.sing_box_log_path.clone())
            .ok_or_else(|| runtime_error("sing-box stop log path is unavailable"))?;
        if self.sing_box.status()?.state == SingBoxManagedProcessState::Running {
            self.sing_box.stop(&log_path)?;
        }
        state.sing_box_running = false;
        state.sing_box_process_id = None;
        state.sing_box_exit_code = self.sing_box.status()?.exit_code;
        state.sing_box_log_path = None;
        self.persist(state)
    }

    fn start_native_mitm(
        &mut self,
        config: &WindowsManagedNativeMitmConfig,
        state: &mut WindowsManagedState,
    ) -> DomainResult<()> {
        if self.native_mitm.is_some() && state.native_mitm_running {
            return Ok(());
        }

        if state.native_mitm_certificate_sha1.is_none() {
            state.native_mitm_certificate_sha1 = Some(
                self.integration
                    .install_root_certificate(&config.ca_certificate_path)?,
            );
            self.persist(state)?;
        }

        let service = build_native_mitm_service(config)?;
        let engine_config = native_mitm_proxy_engine_config(config);
        match service.start(&engine_config) {
            Ok(_) => {
                state.native_mitm_running = true;
                state.native_mitm_listener =
                    Some(format!("{}:{}", config.listen_host, config.listen_port));
                state.native_mitm_last_error = None;
                self.native_mitm = Some(service);
                append_native_mitm_log(
                    &config.log_path,
                    &format!(
                        "native HTTPS MITM started listener={}:{} upstream_socks={}:{}",
                        config.listen_host,
                        config.listen_port,
                        config.upstream_socks_host,
                        config.upstream_socks_port
                    ),
                );
                self.persist(state)
            }
            Err(error) => {
                state.native_mitm_running = false;
                state.native_mitm_listener = None;
                state.native_mitm_last_error = Some(error.message.clone());
                append_native_mitm_log(
                    &config.log_path,
                    &format!("native HTTPS MITM start failed: {}", error.message),
                );
                self.persist(state)?;
                Err(error)
            }
        }
    }

    fn stop_native_mitm(
        &mut self,
        state: &mut WindowsManagedState,
        configured: Option<&WindowsManagedNativeMitmConfig>,
    ) -> DomainResult<()> {
        if let Some(service) = self.native_mitm.take() {
            service.stop(DEFAULT_NATIVE_ENGINE_ID)?;
        }
        if state.native_mitm_running {
            if let Some(config) = configured {
                append_native_mitm_log(&config.log_path, "native HTTPS MITM stopped");
            }
            state.native_mitm_running = false;
            state.native_mitm_listener = None;
            state.native_mitm_last_error = None;
            self.persist(state)?;
        }
        Ok(())
    }

    fn rollback_start(&mut self, state: &mut WindowsManagedState, previous: &WindowsManagedState) {
        if state.native_mitm_running && !previous.native_mitm_running {
            let native_mitm = read_managed_config(&self.config_path)
                .ok()
                .and_then(|config| config.native_mitm);
            let _ = self.stop_native_mitm(state, native_mitm.as_ref());
        }
        if state.sing_box_running && !previous.sing_box_running {
            let log_path = read_managed_config(&self.config_path)
                .ok()
                .and_then(|config| config.sing_box.map(|sing_box| sing_box.log_path));
            if self.stop_sing_box(state, log_path).is_err() {
                // Preserve the running state when rollback cannot stop the child.
            }
        }
        if state.tunnel_running && !previous.tunnel_running {
            if let Ok(config) = read_managed_config(&self.config_path) {
                if let Some(tunnel) = config.tunnel {
                    if let Ok(WindowsCliCommand::TunnelStop(args)) =
                        parse_managed_command(tunnel.stop_arguments())
                    {
                        if self.tunnel.stop(&args).is_ok() {
                            state.tunnel_running = false;
                        }
                    }
                }
            }
        }
        if previous.proxy_snapshot.is_none() {
            let snapshot = state.proxy_snapshot.take();
            if let Some(snapshot) = snapshot {
                if self.integration.restore_system_proxy(&snapshot).is_err() {
                    state.proxy_snapshot = Some(snapshot);
                }
            }
        }
        if previous.certificate_sha1.is_none() {
            let thumbprint = state.certificate_sha1.take();
            if let Some(thumbprint) = thumbprint {
                if self
                    .integration
                    .remove_root_certificate(&thumbprint)
                    .is_err()
                {
                    state.certificate_sha1 = Some(thumbprint);
                }
            }
        }
        if previous.native_mitm_certificate_sha1.is_none() {
            let thumbprint = state.native_mitm_certificate_sha1.take();
            if let Some(thumbprint) = thumbprint {
                if self
                    .integration
                    .remove_root_certificate(&thumbprint)
                    .is_err()
                {
                    state.native_mitm_certificate_sha1 = Some(thumbprint);
                }
            }
        }
        if previous.driver_inf_path.is_none() {
            let inf_path = state.driver_inf_path.take();
            if let Some(inf_path) = inf_path {
                match self.integration.uninstall_driver(&inf_path) {
                    Ok(reboot_required) => state.driver_reboot_required = reboot_required,
                    Err(_) => state.driver_inf_path = Some(inf_path),
                }
            }
        }
    }

    fn read_state_or_default(&self) -> DomainResult<WindowsManagedState> {
        if self.state_path.exists() {
            read_managed_state(&self.state_path)
        } else {
            Ok(WindowsManagedState::default())
        }
    }

    fn persist(&self, state: &WindowsManagedState) -> DomainResult<()> {
        write_managed_state(&self.state_path, state)
    }
}

fn build_native_mitm_service(
    config: &WindowsManagedNativeMitmConfig,
) -> DomainResult<NativeProxyEngineService> {
    let certificate_pem = fs::read_to_string(&config.ca_certificate_path)
        .map_err(|_| runtime_error("native MITM CA certificate material could not be read"))?;
    let private_key_pem = fs::read_to_string(&config.ca_private_key_path)
        .map_err(|_| runtime_error("native MITM CA private key material could not be read"))?;
    if certificate_pem.trim().is_empty() || private_key_pem.trim().is_empty() {
        return Err(runtime_error(
            "native MITM CA certificate and private key material must not be empty",
        ));
    }

    let package = builtin_ad_block_plugin_package();
    let policy_service = AnixOpsMitmPluginService::new();
    let plugin_instance = policy_service.load(
        &package,
        &GrantedPermissions {
            permissions: package.manifest.permissions.clone(),
        },
    )?;
    let hook = NativeHttpMitmPluginHook::new(plugin_instance, std::sync::Arc::new(policy_service));

    Ok(NativeProxyEngineService::new()
        .with_http_mitm_hook(hook)
        .with_tls_mitm_ca_material(NativeTlsMitmCaMaterial::new(
            certificate_pem,
            private_key_pem,
        )))
}

fn native_mitm_proxy_engine_config(config: &WindowsManagedNativeMitmConfig) -> ProxyEngineConfig {
    let outbound_id = "windows-managed-mitm-socks-out".to_string();
    ProxyEngineConfig {
        engine_id: DEFAULT_NATIVE_ENGINE_ID.to_string(),
        config: ConfigSnapshot {
            version: SchemaVersion::new(1),
            profiles: vec!["windows-managed-mitm".to_string()],
            listeners: vec![ListenerDescriptor {
                id: "windows-managed-mitm-http".to_string(),
                enabled: true,
                kind: ListenerKind::Http,
                bind: ListenerBind {
                    host: config.listen_host.clone(),
                    port: config.listen_port,
                },
                network: ListenerNetwork::Tcp,
                route: ListenerRoute::DefaultAction(RouteAction::Proxy {
                    node_id: outbound_id.clone(),
                }),
                tags: vec!["windows-managed-mitm".to_string()],
                metadata: Vec::new(),
            }],
            nodes: vec![NodeDescriptor {
                id: outbound_id,
                name: "Windows managed sing-box SOCKS upstream".to_string(),
                protocol: Protocol::Socks,
                endpoint: Endpoint {
                    host: config.upstream_socks_host.clone(),
                    port: config.upstream_socks_port,
                },
                tags: vec!["windows-managed-mitm".to_string()],
                metadata: Vec::new(),
            }],
            policies: vec![RuleSet {
                id: "windows-managed-mitm-route".to_string(),
                rules: Vec::new(),
                default_action: RouteAction::Proxy {
                    node_id: "windows-managed-mitm-socks-out".to_string(),
                },
            }],
            dns: Vec::new(),
            plugins: Vec::new(),
        },
        nodes: Vec::new(),
        metadata: Vec::new(),
    }
}

fn append_native_mitm_log(path: &Path, message: &str) {
    let result = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{message}")
    })();
    let _ = result;
}

pub fn copy_managed_configuration(source: &Path, destination: &Path) -> DomainResult<()> {
    let config = read_managed_config(source)?;
    platform_windows::managed::write_managed_config(destination, &config)
}

fn parse_managed_command(arguments: Vec<String>) -> DomainResult<WindowsCliCommand> {
    parse_args(arguments).map_err(|_| runtime_error("managed tunnel command could not be parsed"))
}

fn runtime_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_MANAGED_RUNTIME_FAILED_CODE, message)
}
