fn main() {
    let parsed = networkcore_linux::parse_args(std::env::args().skip(1));
    let (format, response) = match parsed {
        Ok(command) => {
            let format = command.format();
            let platform = platform_linux::ReadOnlyLinuxPlatformCapabilityService::new(
                platform_linux::HostLinuxReadOnlyProbe::new(),
            );
            let reader = networkcore_linux::FsConfigReader;
            let lifecycle_host = networkcore_linux::CurrentProcessForegroundLifecycleHost::new();
            let response = if matches!(&command, networkcore_linux::LinuxCliCommand::Start { .. }) {
                match networkcore_linux::native_proxy_engine_service_with_builtin_mitm_plugin() {
                    Ok(native_engine) => {
                        let orchestrator = control_runtime::RuntimeOrchestrator::new(
                            config_core::CoreConfigurationService::new(),
                            platform.clone(),
                            native_engine,
                        );
                        networkcore_linux::handle_entrypoint_with_runtime_and_lifecycle(
                            command,
                            &platform,
                            &orchestrator,
                            &reader,
                            &lifecycle_host,
                        )
                    }
                    Err(error) => networkcore_linux::LinuxCliResponse::failure(
                        command.name(),
                        networkcore_linux::LinuxCliExitCode::EngineDenied,
                        control_domain::Diagnostic::new(
                            control_domain::DiagnosticSeverity::Error,
                            networkcore_linux::CLI_START_ENGINE_DENIED_CODE,
                            format!(
                                "linux start MITM plugin hook could not be loaded: {}",
                                error.message
                            ),
                            Some(networkcore_linux::SOURCE_CLI_START.to_string()),
                        ),
                    ),
                }
            } else if matches!(
                &command,
                networkcore_linux::LinuxCliCommand::InstallSingBox { .. }
                    | networkcore_linux::LinuxCliCommand::RunUrl { .. }
            ) {
                match engine_singbox::GithubSingBoxReleaseInstaller::new() {
                    Ok(sing_box_installer) => {
                        let orchestrator = control_runtime::RuntimeOrchestrator::new(
                            config_core::CoreConfigurationService::new(),
                            platform.clone(),
                            networkcore_linux::UnavailableProxyEngineService,
                        );
                        let sing_box_runner = engine_singbox::CommandSingBoxProcessRunner::new();
                        networkcore_linux::handle_entrypoint_with_runtime_lifecycle_and_sing_box(
                            command,
                            &platform,
                            &orchestrator,
                            &reader,
                            &lifecycle_host,
                            &sing_box_installer,
                            &sing_box_runner,
                        )
                    }
                    Err(error) => networkcore_linux::LinuxCliResponse::failure(
                        command.name(),
                        networkcore_linux::LinuxCliExitCode::GeneralFailure,
                        control_domain::Diagnostic::new(
                            control_domain::DiagnosticSeverity::Error,
                            networkcore_linux::CLI_SING_BOX_INSTALL_FAILED_CODE,
                            error.message,
                            Some(networkcore_linux::SOURCE_CLI_SING_BOX.to_string()),
                        ),
                    ),
                }
            } else if matches!(
                &command,
                networkcore_linux::LinuxCliCommand::MitmCertificateApply { .. }
                    | networkcore_linux::LinuxCliCommand::MitmCertificateRollback { .. }
            ) {
                let certificate_store =
                    networkcore_linux::CommandMitmCertificateArtifactStore::new();
                networkcore_linux::handle_entrypoint_with_certificate_lifecycle_io(
                    command,
                    &platform,
                    &certificate_store,
                )
            } else if matches!(
                &command,
                networkcore_linux::LinuxCliCommand::MitmBrowserCaptureLaunch { .. }
                    | networkcore_linux::LinuxCliCommand::MitmBrowserCaptureVerify { .. }
                    | networkcore_linux::LinuxCliCommand::MitmBrowserCaptureTrafficProof { .. }
                    | networkcore_linux::LinuxCliCommand::MitmBrowserCaptureApply { .. }
                    | networkcore_linux::LinuxCliCommand::MitmBrowserCaptureRollback { .. }
            ) {
                let browser_runner = networkcore_linux::CommandBrowserCaptureProcessRunner::new();
                let endpoint_probe = networkcore_linux::CommandBrowserCaptureEndpointProbe::new();
                let traffic_proof_probe =
                    networkcore_linux::CommandBrowserCaptureTrafficProofProbe::new();
                let pac_store = networkcore_linux::CommandBrowserCapturePacFileStore::new();
                networkcore_linux::handle_entrypoint_with_browser_capture_all_io(
                    command,
                    &platform,
                    &browser_runner,
                    &endpoint_probe,
                    &traffic_proof_probe,
                    &pac_store,
                )
            } else {
                let orchestrator = control_runtime::RuntimeOrchestrator::new(
                    config_core::CoreConfigurationService::new(),
                    platform.clone(),
                    engine_native::NativeProxyEngineService::new(),
                );
                networkcore_linux::handle_entrypoint_with_runtime_and_lifecycle(
                    command,
                    &platform,
                    &orchestrator,
                    &reader,
                    &lifecycle_host,
                )
            };
            (format, response)
        }
        Err(error) => (
            networkcore_linux::OutputFormat::Text,
            networkcore_linux::handle_parse_error(error.into_diagnostic()),
        ),
    };

    let output = networkcore_linux::render_response(&response, format);
    if response.ok {
        println!("{output}");
    } else {
        eprintln!("{output}");
    }

    std::process::exit(response.exit_code.code());
}
