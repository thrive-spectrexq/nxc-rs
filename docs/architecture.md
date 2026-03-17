# Architecture Overview

## Layered Design

| Layer | Technology | Responsibility |
|---|---|---|
| **L6 — AI Reasoning** | Claude / GPT / Gemini | Natural language → nxc command translation, attack chain planning |
| **L5 — Agent Loop** | netsage-agent (Rust) | SSE streaming, tool dispatch, approval gating, conversation history |
| **L4 — NXC Engine** | nxc-* crates (Rust) | Protocol auth, credential spray, module execution, results to nxc-db |
| **L3 — TUI / UX** | Ratatui + nxc panels | Real-time spray progress, Pwn3d! list, topology, credential store |
| **L2 — Protocol Stack** | nxc-protocols (Rust) | SMB/LDAP/WinRM/MSSQL/RDP — native Rust, no impacket |
| **L1 — Auth Engine** | nxc-auth (Rust) | NTLM, Kerberos, certificate — pure Rust cryptography |
| **L0 — Packet Engine** | netsage-capture | Raw packet capture, BPF filtering |

## Component Map

### Existing NetSage Crates

- **netsage** — Main binary: TUI entry point, config loading, event bus init
- **netsage-agent** — Tokio async agent loop, multi-provider LLM client, tool dispatch
- **netsage-tui** — Ratatui-based renderer for chat, dashboards, topology, and nxc panels
- **netsage-tools** — Native Rust networking tools (Ping, DNS, SSH, Port Scan, GeoIP, Traceroute, HTTP Probe)
- **netsage-capture** — libpcap bindings, BPF filter compiler, topology discovery
- **netsage-session** — SQLite persistent session storage (extended for nxc credential store)
- **netsage-common** — Shared types: AppEvent, errors, config structs, NxcError, NxcEvent
- **netsage-config** — TOML configuration loader
- **netsage-auth** — API key management for LLM providers
- **netsage-mcp** — MCP server exposing tools to external clients (Claude Desktop, etc.)

### New NetExec-RS Crates

- **nxc-auth** — Pure Rust authentication engine: NTLM (v1/v2), Kerberos (AS-REQ/TGS-REQ, PKINIT, S4U), certificate auth
- **nxc-protocols** — Protocol handlers: SMB, LDAP, WinRM, RDP, MSSQL, SSH, FTP, VNC, WMI, NFS
- **nxc-modules** — Extensible module system: secretsdump, SAM, LSA, BloodHound, ADCS, Kerberoast, etc.
- **nxc-db** — Credential workspace database: hosts, credentials, auth results, shares
- **nxc-targets** — Target parsing (CIDR, ranges, files) and concurrent execution engine
- **nxc-cli** — `nxc` binary: clap-based CLI with protocol subcommands

## Dependency Graph

```
nxc-cli
 └─▶ nxc-protocols ─▶ nxc-auth
      │              └─▶ netsage-common
      └─▶ nxc-modules ─▶ nxc-protocols
      └─▶ nxc-db ─▶ netsage-session
      └─▶ nxc-targets
      └─▶ netsage-tui   (shared TUI)
      └─▶ netsage-agent (LLM tool registration)
```

## Key Differences: nxc-rs vs Python NetExec

| Aspect | Python NetExec | nxc-rs (Rust) |
|---|---|---|
| Runtime | CPython 3.10+ | Zero runtime — native binary |
| NTLM | impacket (C extensions) | Pure Rust — RustCrypto |
| Kerberos | impacket + krb5 | Pure Rust — rasn/kerberos |
| Concurrency | threading.Thread | Tokio async + semaphore |
| Memory safety | Python GC | Rust borrow checker |
| Binary size | 200MB+ PyInstaller | < 40MB stripped |
| Startup time | 2-5s (Python import) | < 200ms |
| AI integration | None | Full LLM agent loop via NetSage |
| TUI | Rich/termcolor | Ratatui (native Rust) |
| Module system | Python class files | Rust structs (compiled in) |
