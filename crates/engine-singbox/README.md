# engine-singbox

`engine-singbox` is the first public execution engine adapter crate for NetworkCore.

The crate currently provides source contracts for:

- `sing-box` public engine descriptor identity.
- Latest GitHub release metadata parsing.
- Host/target asset selection for official `sing-box-*` archives.
- Downloading the latest selected archive from the official SagerNet GitHub release.
- Verifying the GitHub release asset `sha256:` digest when present.
- Extracting only the `sing-box` executable from `.tar.gz` archives into a NetworkCore-owned engine cache.

The crate does not bundle `sing-box` in NetworkCore release artifacts. It downloads into an operator-visible cache directory at runtime and records version, asset, digest, archive path, executable path, and diagnostics so the control layer can report provenance without leaking host paths outside explicit CLI output.

Windows `.zip` extraction is intentionally not active in this Linux CLI increment. Linux and macOS `.tar.gz` assets are the supported extraction shape for this source contract.
