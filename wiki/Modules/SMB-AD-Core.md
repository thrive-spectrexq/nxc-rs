# SMB & Active Directory Core Modules

These are the bread-and-butter modules for moving laterally and hunting within standard Active Directory networks.

## Privilege Escalation & Domain Admin

*   **`ms17_010`**: Scans the network for the EternalBlue vulnerability.
    ```bash
    nxc smb 10.0.0.0/24 -M ms17_010
    ```
*   **`printnightmare`**: Scans the network for the CVE-2021-1675 Print Spooler vulnerability.
*   **`shadowcoerce`**: Authenticate coercion over the File Server VSS Agent Service (MS-FSRVP).
*   **`backup_operator`**: If you have `SeBackupPrivilege`, this module will automatically volume-shadow-copy the `C:\Windows\NTDS\NTDS.dit` file out the back door without triggering endpoint detection on `ntdsutil`.

## Credential Dumps from SYSVOL

If you have any regular domain user, these modules will rip configuration passwords left on SYSVOL.

*   **`gpp_password`**: Locates `Groups.xml` files and decrypts the `cpassword` string via the Microsoft public AES-256 key (MS14-025).
*   **`gpp_autologin`**: Scrapes auto-logon credentials from `Registry.xml`.

## Evasion & Enumeration

*   **`enum_av`**: Identifies installed EDR/AV utilities by enumerating local system services via MSRPC.
    ```bash
    nxc smb 10.10.10.10 -M enum_av
    ```
*   **`uac`**: Checks if UAC `LocalAccountTokenFilterPolicy` is set, telling you if local admins will get high-integrity execution remotely.
*   **`runasppl`**: Checks if the target `LSASS` process is protected via RunAsPPL by querying the remote registry.
