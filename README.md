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

- **Multi-Protocol Support**: SMB, LDAP, WinRM, RDP, MSSQL, SSH, FTP, VNC, WMI, NFS
- **Authentication Engine**: NTLM (v1/v2), Kerberos (AS-REQ/TGS-REQ, PKINIT, S4U), Pass-the-Hash, Pass-the-Ticket
- **Credential Spraying**: Concurrent multi-target execution engine with lockout detection
- **Module System**: secretsdump, SAM/LSA dump, Kerberoasting, ASREProasting, FTP file listing, NFS share enumeration, BloodHound, ADCS, and 40+ modules
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

## Installation & Local Development

### From Source (All Platforms)

```bash
# Clone the repository
git clone https://github.com/thrive-spectrexq/nxc-rs.git
cd nxc-rs

# Build
cargo build --workspace
```

## Running Locally

### 1. View Global Help
To see all available protocols and global options:
```powershell
cargo run --package nxc -- --help
```

### 2. Protocol-Specific Help
Each protocol has its own set of flags. For example, to see options for the FTP or NFS handlers:
```powershell
# FTP Help
cargo run --package nxc -- ftp --help

# NFS Help
cargo run --package nxc -- nfs --help
```

### 3. Example Execution Commands
Here are a few ways to test the current capabilities (replace `<target>` with a lab IP):

**FTP Navigation**: Authenticate as anonymous and list files.
```powershell
cargo run --package nxc -- ftp <target> -u anonymous -p anonymous --ls
```

**NFS Enumeration**: List exported shares via the MOUNT service.
```powershell
cargo run --package nxc -- nfs <target> --enum-shares
```

**Module Listing**: See which offensive modules are available for a protocol.
```powershell
cargo run --package nxc -- smb <target> -L
```

### 4. Build for Production
If you want to use the compiled binary directly without `cargo run`, you can build a release version:
```powershell
cargo build --release --package nxc
```
The binary will be located at `target\release\nxc.exe` (Windows) or `target/release/nxc` (Unix).

## Usage Examples (Binary)

If you have built the release binary or have it in your path:

```bash
# Password spray a /24
nxc smb 192.168.1.0/24 -u admin -p 'Password123'

# Kerberoasting
nxc ldap dc01.corp.local -u user -p pass --kerberoasting out.txt

# Pass-the-Hash + secretsdump
nxc smb 192.168.1.10 -u admin -H aad3b435b51404ee... -M secretsdump
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
