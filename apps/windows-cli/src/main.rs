fn main() {
    let parsed = networkcore_windows::parse_args(std::env::args().skip(1));
    let (format, response) = match parsed {
        Ok(command) => {
            let format = command.format();
            let platform = platform_windows::ReadOnlyWindowsPlatformCapabilityService::new();
            let response = networkcore_windows::handle_entrypoint(command, &platform);
            (format, response)
        }
        Err(error) => (
            networkcore_windows::OutputFormat::Text,
            networkcore_windows::handle_parse_error(error.into_diagnostic()),
        ),
    };

    let output = networkcore_windows::render_response(&response, format);
    if response.ok {
        println!("{output}");
    } else {
        eprintln!("{output}");
    }

    std::process::exit(response.exit_code.code());
}
