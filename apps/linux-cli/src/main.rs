fn main() {
    let parsed = networkcore_linux::parse_args(std::env::args().skip(1));
    let (format, response) = match parsed {
        Ok(command) => {
            let format = command.format();
            let platform = platform_linux::ReadOnlyLinuxPlatformCapabilityService::new(
                platform_linux::HostLinuxReadOnlyProbe::new(),
            );
            let orchestrator = control_runtime::RuntimeOrchestrator::new(
                config_core::CoreConfigurationService::new(),
                platform.clone(),
                engine_native::NativeProxyEngineService::new(),
            );
            let reader = networkcore_linux::FsConfigReader;
            let lifecycle_host = networkcore_linux::CurrentProcessForegroundLifecycleHost::new();
            let response = networkcore_linux::handle_entrypoint_with_runtime_and_lifecycle(
                command,
                &platform,
                &orchestrator,
                &reader,
                &lifecycle_host,
            );
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
