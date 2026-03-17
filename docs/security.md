# Security & Responsible Use

## Privilege Model

- **Linux**: Uses `CAP_NET_RAW` and `CAP_NET_ADMIN` to avoid full root requirements.
- **macOS**: Prompts for `sudo` or checks `access_bpf` group.
- **Audit**: All actions (especially in AUTONOMOUS mode) are logged to the SQLite session store.

## NetExec-RS Safeguards

### Lockout Detection
Automatic spray halting when `STATUS_ACCOUNT_LOCKED_OUT` responses are detected. Configurable threshold with `--lockout-threshold`.

### Audit-Complete
Every authentication attempt, command execution, and credential access is written to the SQLite audit log with timestamp, target, and user identity.

### Approval Gating
All WRITE/ACTIVE risk tools require explicit TUI approval in Supervised mode — the agent cannot silently dump credentials or execute commands.

### Credential Zeroization
NT hashes and plaintext passwords are zeroized on drop using the `zeroize` crate. They never appear in tracing logs.

### No Persistence
NetExec-RS does not install agents, backdoors, or scheduled tasks without explicit module invocation and user approval.

## Risk Classification

| Risk | Colour | nxc-rs Tools |
|---|---|---|
| **INFO** | Green | `nxc smb enum_hosts` · `nxc ldap get-users` · `nxc ldap get-desc-users` |
| **PROBE** | Yellow | `nxc smb password spray` · `nxc ldap kerberoast` · `nxc ldap asreproast` |
| **ACTIVE** | Orange | `nxc smb exec` · `nxc winrm exec` · `nxc mssql xp_cmdshell` · `nxc rdp` |
| **WRITE** | Red | `nxc smb secretsdump` · `nxc smb sam/lsa` · `nxc ldap daclwrite` |

## Contextual Intelligence: NETWORK.md

Similar to `CLAUDE.md`, NetSage reads a `NETWORK.md` file from the current directory. This provides context like:
- Network topology (subnets, VLANs)
- Known services and ports
- Authorised IP ranges
- SLA thresholds (latency, packet loss)
- Active Directory domain info (for nxc operations)

## Configuration

Configuration is stored in `config.toml`:

```toml
[core]
model = "gemini-2.5-pro"
approval_mode = "supervised"

[capture]
default_interface = "auto"
snaplen = 65535

[nxc]
threads = 256
timeout_secs = 30
lockout_threshold = 3
workspace = "default"
```

## Intended Use Cases

- ✅ Authorized red team and penetration testing engagements
- ✅ Internal security assessments of Active Directory environments
- ✅ Purple team exercises and defensive validation
- ✅ Security research in isolated lab environments
- ✅ CTF (Capture the Flag) competitions

## Ethics

NetExec-RS is a dual-use security research tool. Like the original NetExec, it is designed exclusively for authorized security work. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.
