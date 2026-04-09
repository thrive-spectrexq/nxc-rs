# MSSQL Offensive Modules

Database attacks form a critical lateral movement path. The RS-native TDS implementation supports these aggressive modules.

## Lateral Movement & Execution

*   **`enable_cmdshell`**: Automatically turns on the `xp_cmdshell` advanced option and reconfigures the server (requires `sysadmin` rights).
    ```bash
    nxc mssql 10.0.0.5 -u sa -p sqlpass -M enable_cmdshell
    ```
*   **`exec_on_link`**: If the target server has linked servers out to other systems, this module will execute raw queries or `xp_cmdshell` *through* the DB link.
    ```bash
    nxc mssql 10.0.0.5 -u sa -p sqlpass -M exec_on_link --link DB-DEV-01 --query "select @@servername"
    ```
*   **`mssql_coerce`**: Forces the SQL service account to authenticate out to you via UNC path injection (`xp_dirtree`, `xp_fileexist`), grabbing its hash.

## Loot & Recon

*   **`enum_logins`**: Complete dump of all SQL mapped logins and the respective server roles (sysadmin, securityadmin).
*   **`enum_links`**: Enumerate all external DB Links configured on the instance to draw trust maps down the datacenter.
*   **`mssql_dumper`**: Point, click, and dump entire databases, tables, and schemas straight to local JSON.
