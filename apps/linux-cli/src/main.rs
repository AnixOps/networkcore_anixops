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
                networkcore_linux::UnavailableProxyEngineService::new(),
            );
            let reader = networkcore_linux::FsConfigReader;
            let response = networkcore_linux::handle_entrypoint_with_runtime(
                command,
                &platform,
                &orchestrator,
                &reader,
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
