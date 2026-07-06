fn main() {
    let parsed = networkcore_linux::parse_args(std::env::args().skip(1));
    let (format, response) = match parsed {
        Ok(command) => {
            let format = command.format();
            let response = networkcore_linux::handle_entrypoint_skeleton(command);
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
