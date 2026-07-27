//! Managed Windows runtime shared by the SCM entrypoint and contract tests.

use control_domain::{
    ConfigSnapshot, DomainError, DomainResult, Endpoint, GrantedPermissions, ListenerBind,
    ListenerDescriptor, ListenerKind, ListenerNetwork, ListenerRoute, MitmPluginService,
    NodeDescriptor, PluginPackage, Protocol, ProxyEngineConfig, ProxyEngineLifecycleState,
    ProxyEngineService, RouteAction, RuleSet, SchemaVersion,
};
use engine_mieru::{
    apply_and_start_mieru_client, status_mieru_client, stop_mieru_client, wait_for_mieru_listener,
    CommandMieruCommandRunner, MieruClientControlRequest,
};
use engine_native::{
    NativeHttpMitmPluginHook, NativeNodeScriptExecutor, NativeNodeScriptRuntimeConfig,
    NativeProxyEngineService, NativeTlsMitmCaMaterial, DEFAULT_NATIVE_ENGINE_ID,
};
use engine_singbox::{
    inspect_sing_box_local_selector_snapshot, read_sing_box_clash_api_selector_with_timeout,
    SingBoxManagedProcessRequest, SingBoxManagedProcessState, SingBoxManagedProcessSupervisor,
};
use mitm_policy::{builtin_ad_block_plugin_package, AnixOpsMitmPluginService};
use networkcore_windows::{
    parse_args, OutputFormat, WindowsCliCommand, WindowsTunnelCommandService,
    WindowsTunnelPrepareStorageArgs, WindowsTunnelStatusArgs,
};
use platform_windows::managed::{
    read_managed_config, read_managed_state, write_managed_state, WindowsManagedConfig,
    WindowsManagedNativeMitmConfig, WindowsManagedNativeMitmScriptRuntimeConfig,
    WindowsManagedState, WindowsProxySettings,
};
#[cfg(windows)]
use platform_windows::mitm_security::validate_windows_managed_mitm_private_key;
use platform_windows::system_integration::WindowsSystemIntegration;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const WINDOWS_MANAGED_RUNTIME_FAILED_CODE: &str = "windows.managed.runtime_failed";

pub struct WindowsManagedRuntime<I, T> {
    integration: I,
    tunnel: T,
    sing_box: SingBoxManagedProcessSupervisor,
    mieru: CommandMieruCommandRunner,
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
            mieru: CommandMieruCommandRunner::new(),
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
        self.stop_mieru(&mut state, config.mieru.as_ref())?;
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

        if let Some(sing_box) = config.sing_box.as_ref().filter(|sing_box| sing_box.enabled) {
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

            if let Some(proxy) = config.system_proxy.as_ref().filter(|proxy| proxy.enabled) {
                if let Err(error) = verify_managed_loopback_listener(proxy) {
                    state.sing_box_listener_reachable = false;
                    return self.record_runtime_failure(
                        &mut state,
                        format!(
                            "managed sing-box loopback listener health check failed: {}",
                            error.message
                        ),
                    );
                }
                state.sing_box_listener_reachable = true;
            } else {
                state.sing_box_listener_reachable = false;
            }

            match verify_generated_selector_readback(&sing_box.config_path) {
                Ok(readable) => state.sing_box_control_api_readable = readable,
                Err(error) => {
                    state.sing_box_control_api_readable = false;
                    return self.record_runtime_failure(
                        &mut state,
                        format!(
                            "managed sing-box selector health check failed: {}",
                            error.message
                        ),
                    );
                }
            }
        }

        if let Some(mieru) = &config.mieru {
            if mieru.enabled && state.mieru_running {
                let request = MieruClientControlRequest {
                    executable_path: mieru.executable_path.clone(),
                    expected_sha256: mieru.expected_sha256.clone(),
                    config_path: mieru.config_path.clone(),
                };
                if let Err(error) = status_mieru_client(&self.mieru, &request) {
                    return self.record_runtime_failure(
                        &mut state,
                        format!("managed Mieru status check failed: {}", error.message),
                    );
                }
                match wait_for_mieru_listener(
                    &mieru.socks5_host,
                    mieru.socks5_port,
                    std::time::Duration::from_millis(250),
                ) {
                    Ok(report) => state.mieru_listener = Some(report.endpoint),
                    Err(error) => {
                        state.mieru_listener = None;
                        return self.record_runtime_failure(
                            &mut state,
                            format!("managed Mieru listener check failed: {}", error.message),
                        );
                    }
                }
            }
        }

        if config
            .native_mitm
            .as_ref()
            .is_some_and(|native_mitm| native_mitm.enabled)
        {
            let native_mitm = config
                .native_mitm
                .as_ref()
                .expect("enabled native MITM configuration was checked above");
            if let Err(error) = validate_native_mitm_private_key(&native_mitm.ca_private_key_path) {
                state.native_mitm_running = false;
                state.native_mitm_listener = None;
                if let Err(revoke_error) = self.revoke_native_mitm_certificate(state) {
                    return self.record_runtime_failure(
                        &mut state,
                        format!(
                            "managed native HTTPS MITM private key protection validation failed and the managed CA could not be revoked: {}",
                            revoke_error.message
                        ),
                    );
                }
                return self.record_runtime_failure(
                    &mut state,
                    format!(
                        "managed native HTTPS MITM private key protection validation failed: {}",
                        error.message
                    ),
                );
            }
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

        if config
            .mieru
            .as_ref()
            .map(|mieru| !mieru.enabled)
            .unwrap_or(true)
            && state.mieru_running
        {
            self.stop_mieru(state, config.mieru.as_ref())?;
        }

        if let Some(sing_box) = &config.sing_box {
            if sing_box.enabled {
                let request = SingBoxManagedProcessRequest {
                    executable_path: sing_box.executable_path.clone(),
                    config_path: sing_box.config_path.clone(),
                    working_directory: sing_box.working_directory.clone(),
                    log_path: sing_box.log_path.clone(),
                };
                state.sing_box_config_validated = false;
                self.persist(state)?;
                SingBoxManagedProcessSupervisor::check_configuration(&request)?;
                let current_status = self.sing_box.status()?;
                let status = if current_status.state == SingBoxManagedProcessState::Running {
                    current_status
                } else {
                    self.sing_box.start(&request)?
                };
                state.sing_box_running = status.state == SingBoxManagedProcessState::Running;
                state.sing_box_config_validated = state.sing_box_running;
                state.sing_box_listener_reachable = false;
                state.sing_box_control_api_readable = false;
                state.sing_box_process_id = status.process_id;
                state.sing_box_exit_code = status.exit_code;
                state.sing_box_log_path = Some(sing_box.log_path.clone());
                if let Some(proxy) = config.system_proxy.as_ref().filter(|proxy| proxy.enabled) {
                    verify_managed_loopback_listener(proxy)?;
                    state.sing_box_listener_reachable = true;
                }
                state.sing_box_control_api_readable =
                    verify_generated_selector_readback(&sing_box.config_path)?;
                self.persist(state)?;
            }
        }

        if let Some(mieru) = &config.mieru {
            if mieru.enabled && !state.mieru_running {
                let request = MieruClientControlRequest {
                    executable_path: mieru.executable_path.clone(),
                    expected_sha256: mieru.expected_sha256.clone(),
                    config_path: mieru.config_path.clone(),
                };
                let report = apply_and_start_mieru_client(&self.mieru, &request)?;
                // Mark the spawned core before the next health authority so a
                // failed readback enters rollback with an explicit stop target.
                state.mieru_running = report.started;
                state.mieru_listener = None;
                self.persist(state)?;
                // Confirm Mieru's own control-plane status before a later
                // listener check permits the managed proxy to be applied.
                status_mieru_client(&self.mieru, &request)?;
                let listener = wait_for_mieru_listener(
                    &mieru.socks5_host,
                    mieru.socks5_port,
                    std::time::Duration::from_secs(5),
                )?;
                state.mieru_listener = Some(listener.endpoint);
                state.mieru_last_error = None;
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
        state.sing_box_config_validated = false;
        state.sing_box_listener_reachable = false;
        state.sing_box_control_api_readable = false;
        state.sing_box_process_id = None;
        state.sing_box_exit_code = self.sing_box.status()?.exit_code;
        state.sing_box_log_path = None;
        self.persist(state)
    }

    fn stop_mieru(
        &mut self,
        state: &mut WindowsManagedState,
        configured: Option<&platform_windows::managed::WindowsManagedMieruConfig>,
    ) -> DomainResult<()> {
        if !state.mieru_running {
            return Ok(());
        }
        let config = configured.ok_or_else(|| {
            runtime_error("Mieru is marked running but its managed configuration is unavailable")
        })?;
        let report = stop_mieru_client(
            &self.mieru,
            &MieruClientControlRequest {
                executable_path: config.executable_path.clone(),
                expected_sha256: config.expected_sha256.clone(),
                config_path: config.config_path.clone(),
            },
        )?;
        state.mieru_running = !report.stopped;
        state.mieru_last_error = None;
        state.mieru_listener = None;
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

        if let Err(error) = validate_native_mitm_private_key(&config.ca_private_key_path) {
            self.revoke_native_mitm_certificate(state)?;
            return Err(error);
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

    /// A private-key ACL drift invalidates the security basis for trusting its
    /// CA. Revoke the managed trust entry before the normal runtime rollback.
    fn revoke_native_mitm_certificate(&self, state: &mut WindowsManagedState) -> DomainResult<()> {
        let Some(thumbprint) = state.native_mitm_certificate_sha1.take() else {
            return Ok(());
        };
        if let Err(error) = self.integration.remove_root_certificate(&thumbprint) {
            state.native_mitm_certificate_sha1 = Some(thumbprint);
            return Err(error);
        }
        self.persist(state)
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
        if state.mieru_running && !previous.mieru_running {
            if let Ok(config) = read_managed_config(&self.config_path) {
                if self.stop_mieru(state, config.mieru.as_ref()).is_err() {
                    state.mieru_last_error = Some(
                        "Mieru rollback could not issue the official stop command".to_string(),
                    );
                }
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

    let mut package = builtin_ad_block_plugin_package();
    if let Some(script_runtime) = &config.script_runtime {
        package = PluginPackage {
            manifest: package.manifest,
            source: fs::read_to_string(&script_runtime.policy_source_path).map_err(|_| {
                runtime_error("native MITM script runtime policy source could not be read")
            })?,
        };
    }
    let policy_service = AnixOpsMitmPluginService::new();
    let plugin_instance = policy_service.load(
        &package,
        &GrantedPermissions {
            permissions: package.manifest.permissions.clone(),
        },
    )?;
    let hook = NativeHttpMitmPluginHook::new(plugin_instance, std::sync::Arc::new(policy_service));
    let hook = match config.script_runtime.as_ref() {
        Some(script_runtime) => {
            hook.with_node_script_executor(build_native_node_script_executor(script_runtime)?)
        }
        None => hook,
    };

    Ok(NativeProxyEngineService::new()
        .with_http_mitm_hook(hook)
        .with_tls_mitm_ca_material(NativeTlsMitmCaMaterial::new(
            certificate_pem,
            private_key_pem,
        )))
}

/// ACL enforcement is a Windows runtime boundary. Linux-hosted data-plane
/// contract tests use disposable CA files and do not emulate a Windows DACL.
#[cfg(windows)]
fn validate_native_mitm_private_key(path: &Path) -> DomainResult<()> {
    validate_windows_managed_mitm_private_key(path)
}

#[cfg(not(windows))]
fn validate_native_mitm_private_key(_path: &Path) -> DomainResult<()> {
    Ok(())
}

fn build_native_node_script_executor(
    config: &WindowsManagedNativeMitmScriptRuntimeConfig,
) -> DomainResult<NativeNodeScriptExecutor> {
    if !config.policy_source_path.is_file()
        || !config.runner_path.is_file()
        || config.script_maps.values().any(|path| !path.is_file())
    {
        return Err(runtime_error(
            "native MITM script runtime requires existing local policy, runner, and script files",
        ));
    }
    let script_assets = config
        .script_maps
        .iter()
        .map(|(url, path)| (url.clone(), path.display().to_string()))
        .collect::<BTreeMap<_, _>>();
    Ok(NativeNodeScriptExecutor::new(
        NativeNodeScriptRuntimeConfig {
            node_binary: config.node_binary.clone(),
            runner_path: config.runner_path.display().to_string(),
            script_assets,
            persistent_store_path: config
                .persistent_store_path
                .as_ref()
                .map(|path| path.display().to_string()),
            max_timeout_ms: 30_000,
            max_body_bytes: 64 * 1024,
        },
    ))
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

fn verify_managed_loopback_listener(proxy: &WindowsProxySettings) -> DomainResult<()> {
    let endpoint = proxy.server.parse::<SocketAddr>().map_err(|_| {
        runtime_error("managed system proxy endpoint must be an explicit loopback socket address")
    })?;
    if !endpoint.ip().is_loopback() {
        return Err(runtime_error(
            "managed system proxy endpoint must use a loopback address",
        ));
    }
    TcpStream::connect_timeout(&endpoint, Duration::from_millis(250)).map_err(|_| {
        runtime_error("managed sing-box loopback listener was not reachable after start")
    })?;
    Ok(())
}

fn verify_generated_selector_readback(config_path: &Path) -> DomainResult<bool> {
    let content = fs::read_to_string(config_path).map_err(|_| {
        runtime_error("managed sing-box configuration could not be read for health")
    })?;
    let Some(selector) = inspect_sing_box_local_selector_snapshot(&content) else {
        return Ok(false);
    };
    let status = read_sing_box_clash_api_selector_with_timeout(
        &selector.controller,
        Duration::from_millis(250),
    )?;
    if status.current_outbound_tag != selector.selected_outbound_tag {
        return Err(runtime_error(
            "managed sing-box selector readback did not match its generated profile",
        ));
    }
    Ok(true)
}
