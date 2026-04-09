# RS-Exclusive Advanced Capabilities

Because NetExec-RS is compiled in Rust, we have raw memory pointers, high-performance serialization, and syscall capability. The **RS-Exclusive** suite is an evolution far past standard Python-built tooling.

## Defense Evasion (In-Memory)

*   **`amsi_bypass`**: Injects logic into the remote system that patches the Antimalware Scan Interface (`amsi.dll`'s `AmsiScanBuffer` function) with a successful return code (0x80070057) prior to executing any script modules.
    ```bash
    nxc smb 10.0.0.0/24 -M amsi_bypass
    ```
*   **`etw_patcher`**: Nulls out Event Tracing for Windows (`ntdll.dll!EtwEventWrite`) via remote process thread hijacking, blinding EDR telemetry sensors from your payload.
*   **`defender_enum`**: Rips the active Microsoft Defender configuration and lists exactly which folders, processes, and extensions are in the Exclusions list.

## Native Execution

*   **`bof_loader`**: Instead of executing noisy PowerShell or C# binaries, NetExec-RS has a built-in Cobalt Strike Beacon Object File (BOF) loader. You can pass raw `.o` files containing C code, and the engine will natively link and execute them inside the target memory over SMB.
    ```bash
    nxc smb 10.10.10.10 -M bof_loader -f ./whoami.o
    ```
*   **`pe_loader`**: Reflectively loads Windows PE (Portable Executable) `.exe` payloads directly from your local disk into the memory space of a remote target process using Process Hollowing techniques.

## Active Directory Extracurriculars

*   **`dpapi_masterkey`**: A powerful Rust-driven decryption process to steal DPAPI Master Keys from Domain Controllers, enabling you to decrypt almost any user's local protected secrets fleet-wide natively without needing Mimikatz.
