# ◈ NetExec-RS ◈

**Network Execution Tool — Pure Rust Rewrite**

---

| | |
|---|---|
| **Project** | NetExec-RS (`nxc-rs`) |
| **Base Platform** | NetSage v0.2→1.0 Workspace |
| **Language** | Pure Rust 2021 Edition |
| **Architecture** | Cargo Workspace Monorepo (extends NetSage) |
| **Async Runtime** | Tokio (full features) |
| **TUI Framework** | Ratatui 0.28 (inherits NetSage TUI) |
| **Target Protocols** | SMB · LDAP · WinRM · RDP · MSSQL · SSH · FTP · VNC · WMI · NFS |
| **Auth Methods** | Password · NTLM Hash · Kerberos TGT/TGS · Certificate |
| **Min Rust Version** | 1.80.0 |
| **Target Platforms** | Linux · macOS · Windows |

## Overview

NetExec-RS is a full Rust reimplementation of the [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) network execution and penetration testing framework, built as a seamless extension of the existing **NetSage** workspace architecture.

Where NetSage provides AI-powered network intelligence, diagnostics, and packet capture, NetExec-RS adds the **offensive and assessment layer**: multi-protocol authentication, credential spraying, post-exploitation modules, Active Directory enumeration, and lateral movement automation.

### Design North Stars

- **Zero-dependency single binary** — no Python runtime, no impacket, no external tools
- **Memory-safe protocol implementation** — all SMB/NTLM/Kerberos implemented natively in Rust
- **NetSage-native** — shares TUI, session store, agent loop, and event bus with NetSage
- **NetExec CLI parity** — same `nxc <protocol> <targets> -u -p` idiom, compatible flags
- **AI-augmented execution** — LLM agent can invoke nxc tools via the existing tool registry
- **Audit-complete** — every authentication attempt and command execution logged to SQLite

## Features

- **Multi-Protocol Support**: SMB, LDAP, WinRM, RDP, MSSQL, SSH, FTP, VNC, WMI, NFS
- **Authentication Engine**: NTLM (v1/v2), Kerberos (AS-REQ/TGS-REQ, PKINIT, S4U), Pass-the-Hash, Pass-the-Ticket
- **Credential Spraying**: Concurrent multi-target execution engine with lockout detection
- **Module System**: secretsdump, SAM/LSA dump, Kerberoasting, BloodHound, ADCS, and 30+ modules
- **Credential Database**: SQLite workspace-aware cred store (`nxcdb` equivalent)
- **AI Integration**: LLM agent invokes nxc tools via NetSage's ToolRegistry with approval gating
- **Live TUI**: Real-time spray progress, Pwn3d! host list, credential store — all in the NetSage Ratatui interface
- **Multi-Model Support**: Integrated with **Anthropic Claude**, **OpenAI GPT**, and **Google Gemini**
- **Topology Visualization**: Real-time ASCII network mapping (`Ctrl+T`)
- **Audit Logging**: Every action recorded in a SQLite session store

## Workspace Layout

```
netsage/                          # Workspace root
├── Cargo.toml                    # [workspace] manifest
├── crates/                       # Core crates
│   ├── netsage/                  # ◈ nxc binary (unified entry point)
│   ├── agent/                    # LLM agent loop + nxc tool dispatch
│   ├── tui/                      # Ratatui TUI + nxc panels
│   ├── tools/                    # Tool registry (network + nxc tools)
│   ├── capture/                  # Packet capture engine
│   ├── session/                  # SQLite session store + nxc cred store
│   ├── common/                   # Shared types — NxcError, NxcEvent
│   ├── config/                   # Configuration loader
│   ├── auth/                     # API key management
│   └── mcp/                      # MCP server — tools auto-exposed
├── nxc-rs/                       # NetExec-RS protocol & auth crates
│   ├── nxc-auth/                 # NTLM, Kerberos, password auth engines
│   ├── nxc-protocols/            # SMB, LDAP, WinRM, RDP, MSSQL, SSH…
│   ├── nxc-modules/              # Module system (secretsdump, etc.)
│   ├── nxc-db/                   # Credential workspace / nxcdb equiv
│   └── nxc-targets/              # Target parsing: CIDR, ranges, files
├── config/
│   └── nxc.toml                  # nxc-specific defaults
├── config.toml                   # Main config
└── NETWORK.md                    # Network context file
```

## Installation

### From Source (All Platforms)

```bash
# Clone the repository
git clone https://github.com/thrive-spectrexq/netsage.git
cd netsage

# Build
cargo build --release --workspace

# The binary is at:
#   target/release/nxc
#
# Run without args → interactive TUI
# Run with protocol → CLI mode (e.g. nxc smb 192.168.1.0/24 -u admin -p pass)
```

### One-Line Install

**Linux / macOS:**
```bash
curl -sSL https://raw.githubusercontent.com/thrive-spectrexq/netsage/master/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/thrive-spectrexq/netsage/master/install.ps1 | iex
```

### Windows Build Requirements

To build on Windows, you need the **Npcap SDK** for the packet engine:
1. Download from [nmap.org/npcap/](https://nmap.org/npcap/)
2. Extract and set `LIB` to point to the `Lib\x64` folder

### Configuration

1. Set your API key:
   - **Windows**: `$env:GEMINI_API_KEY = "your_key_here"`
   - **Linux/macOS**: `export GEMINI_API_KEY=your_key_here`
2. Create a `NETWORK.md` file for network context
3. Select provider in `config.toml`:
   ```toml
   [core]
   provider = "gemini"
   model = "gemini-2.5-pro"
   ```

## Usage

### Interactive TUI (default)

```bash
# Launch — no arguments opens the AI-powered TUI
nxc
```

### Protocol CLI Mode

```bash
# Password spray a /24
nxc smb 192.168.1.0/24 -u admin -p 'Password123'

# Kerberoasting
nxc ldap dc01.corp.local -u user -p pass --kerberoasting out.txt

# Pass-the-Hash + secretsdump
nxc smb 192.168.1.10 -u admin -H aad3b435b51404ee... -M secretsdump

# See all options
nxc --help
```

### AI-Assisted Assessment

```
> I have admin:Password1 for corp.local — do a full assessment
# Agent runs nxc tools automatically with approval gates
```

## Key Commands

| Key | Action |
|---|---|
| `q` | Quit |
| `Ctrl+T` | Toggle Topology View |
| `/clear` | Clear investigation history |
| `/export` | Generate Markdown report |

## Architecture

| Layer | Technology | Responsibility |
|---|---|---|
| **L6 — AI Reasoning** | Claude / GPT / Gemini | Natural language → nxc command translation |
| **L5 — Agent Loop** | netsage-agent (Rust) | SSE streaming, tool dispatch, approval gating |
| **L4 — NXC Engine** | nxc-* crates (Rust) | Protocol auth, credential spray, module execution |
| **L3 — TUI / UX** | Ratatui + nxc panels | Real-time spray progress, Pwn3d! list, topology |
| **L2 — Protocol Stack** | nxc-protocols (Rust) | SMB/LDAP/WinRM/MSSQL/RDP — native Rust |
| **L1 — Auth Engine** | nxc-auth (Rust) | NTLM, Kerberos, certificate — pure Rust |
| **L0 — Packet Engine** | netsage-capture | Raw packet capture, BPF filtering |

## Security & Responsible Use

NetExec-RS is a **dual-use security research tool** designed exclusively for **authorized penetration testing** and security assessments.

**Built-in Safeguards:**
- 🔒 **Lockout Detection** — automatic spray halting on `STATUS_ACCOUNT_LOCKED_OUT`
- 📋 **Audit-Complete** — every auth attempt logged to SQLite with timestamp
- ✅ **Approval Gating** — WRITE/ACTIVE tools require TUI approval in Supervised mode
- 🧹 **Credential Zeroization** — secrets zeroized on drop, never in logs

**Intended Use Cases:**
- Authorized red team and penetration testing
- Internal security assessments of Active Directory
- Purple team exercises and defensive validation
- Security research in isolated lab environments
- CTF competitions

## License

See [LICENSE](LICENSE) for details.
