# ◈ NetExec-RS ◈

**Network Execution Tool — Pure Rust**

---

| | |
|---|---|
| **Project** | NetExec-RS (`nxc-rs`) |
| **Language** | Pure Rust 2021 Edition |
| **Architecture** | Cargo Workspace (`nxc` binary) |
| **Async Runtime** | Tokio (full features) |
| **Target Protocols** | SMB · LDAP · WinRM · RDP · MSSQL · SSH · FTP · VNC · WMI · NFS |
| **Auth Methods** | Password · NTLM Hash · Kerberos TGT/TGS · Certificate |
| **Min Rust Version** | 1.94.0 |
| **Target Platforms** | Linux · macOS · Windows |

## Overview

NetExec-RS is a native Rust reimplementation of the [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec) network execution framework. It is focused entirely on **offensive capability and Active Directory assessment**: multi-protocol authentication, credential spraying, post-exploitation module execution, and lateral movement automation.

### Design Principles

- **Zero-dependency binary** — no Python runtime, no impacket, no external tools
- **Memory-safe protocol implementation** — all SMB/NTLM/Kerberos implemented natively in Rust
- **Execution engine parity** — consistent `nxc <protocol> <targets> -u -p` CLI idiom.
- **Concurrent Spray Engine** - heavily multithreaded Tokio execution for speed.

## Features

- **Multi-Protocol Support**: SMB, LDAP, WinRM, RDP, MSSQL, SSH, FTP, VNC, WMI, NFS (Pending impl)
- **Authentication Engine**: NTLM (v1/v2), Kerberos (AS-REQ/TGS-REQ, PKINIT, S4U), Pass-the-Hash, Pass-the-Ticket
- **Credential Spraying**: Concurrent multi-target execution engine with lockout detection
- **Module System**: secretsdump, SAM/LSA dump, Kerberoasting, BloodHound, ADCS, and 30+ modules
- **Credential Database**: SQLite workspace-aware cred store (`nxcdb` equivalent)

## Workspace Layout

```
nxc-rs/                           # Workspace root
├── Cargo.toml                    # [workspace] manifest
└── nxc-rs/                       # Sub-crates
    ├── nxc/                      # ◈ nxc binary (CLI entry point)
    ├── auth/                     # NTLM, Kerberos, password auth engines
    ├── protocols/                # SMB, LDAP, WinRM, RDP, MSSQL, SSH…
    ├── modules/                  # Module system (secretsdump, etc.)
    ├── db/                       # Credential workspace / nxcdb equiv
    └── targets/                  # Target parsing: CIDR, ranges, files
```

## Installation

### From Source (All Platforms)

```bash
# Clone the repository
git clone https://github.com/thrive-spectrexq/nxc-rs.git
cd nxc-rs

# Build
cargo build --release --workspace

# The binary is at:
#   target/release/nxc
#
# Run with protocol → CLI mode (e.g. nxc smb 192.168.1.0/24 -u admin -p pass)
```

## Usage

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

## Architecture

| Layer | Responsibility |
|---|---|
| **L3 — CLI UX** | CLI parsing and results formatting |
| **L2 — NXC Engine** | Protocol routing, credential spraying via Tokio pool, tracking nxcdb |
| **L1 — Protocol Stack** | SMB/LDAP/WinRM/MSSQL/RDP network handling |
| **L0 — Auth Engine** | NTLM, Kerberos, certificate crypto math |

## Security & Responsible Use

NetExec-RS is designed exclusively for **authorized penetration testing** and security assessments.

**Intended Use Cases:**
- Authorized red team and penetration testing
- Internal security assessments of Active Directory
- Purple team exercises and defensive validation
- Security research in isolated lab environments
- CTF competitions

## License

See [LICENSE](LICENSE) for details.
