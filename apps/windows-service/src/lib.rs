//! Managed Windows runtime shared by the SCM entrypoint and contract tests.

use control_domain::{DomainError, DomainResult};
use networkcore_windows::{
    parse_args, OutputFormat, WindowsCliCommand, WindowsTunnelCommandService,
    WindowsTunnelPrepareStorageArgs, WindowsTunnelStatusArgs,
};
use platform_windows::managed::{
    read_managed_config, read_managed_state, write_managed_state, WindowsManagedConfig,
    WindowsManagedState,
};
use platform_windows::system_integration::WindowsSystemIntegration;
use std::path::{Path, PathBuf};

pub const WINDOWS_MANAGED_RUNTIME_FAILED_CODE: &str = "windows.managed.runtime_failed";

pub struct WindowsManagedRuntime<I, T> {
    integration: I,
    tunnel: T,
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
            config_path,
            state_path,
        }
    }

    pub fn start(&mut self) -> DomainResult<WindowsManagedState> {
        let config = read_managed_config(&self.config_path)?;
        let mut state = self.read_state_or_default()?;
        let previous = state.clone();
        state.last_transition = "starting".to_string();
        self.persist(&state)?;

        let result = self.apply_configuration(&config, &mut state);
        match result {
            Ok(()) => {
                state.last_transition = "running".to_string();
                self.persist(&state)?;
                Ok(state)
            }
            Err(error) => {
                self.rollback_start(&mut state, &previous);
                state.last_transition = "failed".to_string();
                let _ = self.persist(&state);
                Err(error)
            }
        }
    }

    pub fn stop(&mut self) -> DomainResult<WindowsManagedState> {
        let config = read_managed_config(&self.config_path)?;
        let mut state = self.read_state_or_default()?;
        state.last_transition = "stopping".to_string();
        self.persist(&state)?;

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

    pub fn purge(&mut self) -> DomainResult<WindowsManagedState> {
        let mut state = self.stop()?;
        if let Some(thumbprint) = state.certificate_sha1.take() {
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

        if state.proxy_snapshot.is_none() {
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
                if self.tunnel.status(&status).is_ok() {
                    return Ok(());
                }
                state.tunnel_running = false;
                self.persist(state)?;
            }

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

        Ok(())
    }

    fn rollback_start(&mut self, state: &mut WindowsManagedState, previous: &WindowsManagedState) {
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
