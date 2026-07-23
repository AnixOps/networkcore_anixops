AnixOps NetworkCore Windows portable package

1. Extract the entire directory to a writable location.
2. Run networkcore-windows-gui.exe. Approve the administrator prompt when
   using service, proxy, certificate, or driver operations.
3. The bundled managed-config.json is inert. Import an edited configuration in
   the GUI before starting managed network features.
4. Click Install service, then Start, only when a Windows service is wanted.

The portable ZIP does not register or start the service during extraction.
Managed configuration, state, and logs are stored under:

  %ProgramData%\AnixOps\NetworkCore

To remove a service installed from the portable package, run this command from
an Administrator terminal before deleting the extracted directory:

  networkcore-windows-service.exe purge
  networkcore-windows-service.exe uninstall

sing-box is not bundled. When enabled in managed-config.json, executable_path
must point to an operator-staged, verified sing-box.exe. root_certificate_path
only manages Windows trust; this build does not provide a Windows HTTPS MITM
data plane.
