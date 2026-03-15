# Security & Configuration

## Privilege Model
- **Linux**: Uses `CAP_NET_RAW` and `CAP_NET_ADMIN` to avoid full root requirements.
- **macOS**: Prompts for `sudo` or checks `access_bpf` group.
- **Audit**: All actions (especially in AUTONOMOUS mode) are logged to the SQLite session store.

## Contextual Intelligence: NETWORK.md
Similar to `CLAUDE.md`, NetSage reads a `NETWORK.md` file from the current directory. This provides context like:
- Network topology (subnets, VLANs).
- Known services and ports.
- Authorised IP ranges.
- SLA thresholds (latency, packet loss).

## Configuration
Configuration is stored in `~/.netsage/config.toml`:

```toml
[core]
model = "claude-sonnet-4-6"
approval_mode = "supervised"

[capture]
default_interface = "auto"
snaplen = 65535
```
