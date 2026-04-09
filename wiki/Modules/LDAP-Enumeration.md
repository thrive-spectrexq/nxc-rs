# LDAP & Reconnaissance Modules

LDAP is the lifeblood of Active Directory. NetExec-RS connects asynchronously to extract directory information with blazing speed.

*(For detailed execution instructions, see [ProtocolGuide: LDAP](../Protocols/LDAP-Protocol.md).)*

## Advanced Attack Paths

*   **`bloodhound` / `bloodhound_rs`**: Our custom SharpHound alternative built in Rust. Streams all AD objects (Users, Computers, GPOs, OUs) into BloodHound-compatible JSON files offline.
*   **`delegation`**: Automatically mines LDAP for Unconstrained and Constrained Kerberos delegation paths.
*   **`rbcd`**: (Resource-Based Constrained Delegation). Manipulates the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute.
    ```bash
    nxc ldap 10.0.0.5 -u attacker_machine$ -p pass -M rbcd --target dc01$
    ```
*   **`daclread`**: Dumps and visualizes DACLs/ACEs for targeted objects to easily surface `GenericAll` or `WriteOwner` misconfigurations.

## Enumeration & Password Analysis

*   **`get_unixpassword`**: Scans user objects for plaintext or hashed `unixUserPassword` and `userPassword` attributes often left by legacy macOS/Linux integrations.
*   **`pso`**: Extracts Fine-Grained Password Policies (Password Settings Objects) from LDAP.
*   **`pre2k`**: Scans for "Pre-Windows 2000" backward-compatible objects which often have their NT password identically set to their hostname.

## Infrastructure Recon

*   **`subnets`**: Rapidly pulls the entire enterprise IP routing logic from the AD Sites & Services subnet configuration.
*   **`obsolete`**: Dumps computer accounts matched against EOL/Unsupported Operation System strings (e.g. "Windows 7", "Windows Server 2008").
