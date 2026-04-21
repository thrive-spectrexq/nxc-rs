# ◈ NetExec-RS (nxc-rs) ◈

[![Rust](https://img.shields.io/badge/rustc-1.94.0+-orange.svg?style=flat-square)](https://www.rust-lang.org/)
[![Release](https://img.shields.io/github/v/release/thrive-spectrexq/nxc-rs?color=blue&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/thrive-spectrexq/nxc-rs/build-binaries.yml?branch=master&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/actions)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg?style=flat-square)](LICENSE)

---

**NetExec-RS (nxc-rs)** is a modern, high-performance **Rust implementation inspired by the original Python-based [NetExec](https://github.com/Pennyw0rth/NetExec.git)**.

By leveraging Rust, NetExec-RS benefits from:

- Memory safety without garbage collection  
- Zero-cost abstractions  
- High-performance async execution (Tokio)  
- Strong type guarantees for protocol correctness  

The result is a **next-generation offensive security framework** focused on speed, scalability and reliability.

---

## Key Features

- **Blazing Fast**  
  Built on Tokio's async runtime for massive concurrency across large networks.

- **Pure Rust**  
  No Python or Impacket dependencies. Native implementations include:
  - NTLM SSP  
  - Kerberos  
  - SMB stack  

- **Stealthy & Robust**
  - Lockout detection  
  - Jitter/random delays  
  - Secure TLS handling  

- **AI Mission Orchestrator**
  - Natural language control via LLMs  
  - Autonomous reconnaissance  
  - Multi-step attack chaining  

- **Advanced Recon**
  - AD CS enumeration  
  - BloodHound integration  
  - WMI reconnaissance  

---

## Protocols & Capabilities

Supports **22 protocols** and **135+ modules**.

| Protocol | Status | Capabilities |
| :--- | :--- | :--- |
| **SMB** | ✅ | NTLM SSP, shares, smbexec, lsassy, dcshadow, dumping |
| **LDAP** | ✅ | Enum, AD CS, BloodHound, roasting, gMSA, LAPS |
| **SSH** | ✅ | Auth, exec, sudo checks |
| **WinRM** | ✅ | NTLM/Kerberos, PSRP, command exec |
| **MSSQL** | ✅ | Queries, xp_cmdshell, impersonation |
| **WMI** | ✅ | Exec, system enumeration |
| **ADB** | ✅ | Shell, screenshots |
| **RDP** | ✅ | NLA, screenshots |
| **VNC** | ✅ | Auth, screenshots |
| **FTP/NFS** | ✅ | Listing, share enumeration |
| **HTTP** | ✅ | Web recon |
| **DNS** | ✅ | AXFR, records |
| **IPMI** | ✅ | RAKP dumping |
| **iLO/iDRAC** | ✅ | Redfish probing |
| **Kube** | ✅ | Kubernetes enumeration |

---

## Installation & Setup

### One-Line Install (Recommended)

**Linux / macOS:**
```bash
curl -sSf https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.sh | bash
```

**Windows (PowerShell):**
```powershell
iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.ps1')
```

### Building from Source Manually

**Requirement:** `rustc 1.94.0` or newer.


```bash
# Clone the repository
git clone https://github.com/thrive-spectrexq/nxc-rs.git
cd nxc-rs

# Build all workspace packages
cargo build --workspace
```

---

## Local Development & Usage

### 1. View Global Help
To see all available protocols and global options:
```powershell
cargo run --package nxc -- --help
```

### 2. Protocol-Specific Help
Each protocol has its own set of flags. For example, to see options for the newly implemented **FTP** or **NFS** handlers:
```powershell
# FTP Help
cargo run --package nxc -- ftp --help

# WinRM Help
cargo run --package nxc -- winrm --help
```

### 3. AI Mission Control (CLI)
The **Elite Reaper** AI orchestrator can be launched directly from the CLI for autonomous missions. It supports conversational multi-turn interaction.

**Environment Setup**:
Set one of the following environment variables (the engine will auto-detect which provider to use):
- `GEMINI_API_KEY` (Default, recommended)
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `OLLAMA_API_BASE`

**Launch an Initial Mission**:
```powershell
cargo run --package nxc -- ai "Find hosts on 192.168.1.0/24 with SMB signing disabled"
```

**Conversation Examples**:
- **SMB & Discovery**: `ai "Scan 10.0.0.0/24 for port 445 and identify OS versions"`
- **LDAP Recon**: `ai "Enumerate all GPO names from the domain using ldap protocol"`
- **Web Audit**: `ai "Check if 192.168.1.50 has any active web directories on port 80 or 443"`
- **Credential Auditing**: `ai "Audit 172.16.5.0/24 for default passwords on mssql and ssh services"`

*Type `quit`, `exit`, or `bye` to end the session.*

### 4. Build for Production
If you want to use the compiled binary directly without `cargo run`, you can build a release version:
```powershell
cargo build --release --package nxc
```
The binary will be located at `target\debug\nxc.exe` (Windows) or `target/release/nxc` (Linux).

### View Global Help
To see all available protocols and global options:
```powershell
nxc --help
```

### Protocol-Specific Help
Each protocol has its own set of flags. For example, to see options for the newly implemented **FTP** or **NFS** handlers:
```powershell
# FTP Help
nxc ftp --help

# WinRM Help
nxc winrm --help
```

### Example Execution Commands
Here are a few ways to test the current capabilities (replace `<target>` with a lab IP or CIDR):

**WinRM PSRP Execution**: Run PowerShell commands securely via WinRM.
```powershell
nxc winrm <target> -u Admin -p Pass123 -x "Get-Process"
```

**SMB LSA Dumping**: Dump LSA secrets from an entire /24 subnet.
```powershell
nxc smb 192.168.1.0/24 -u Admin -H 31d6cfe0d16ae931b73c59d7e0c089c0 -M lsassy
```

**NFS Enumeration**: List exported shares via the MOUNT service.
```powershell
nxc nfs <target> --enum-shares
```

**Module Listing**: See which offensive modules are available for a protocol.
```powershell
nxc smb <target> -L
```
**Launch an Initial Mission**:
```powershell
nxc ai "Find hosts on 192.168.1.0/24 with SMB signing disabled"
```
---

## Architecture

NetExec-RS is designed with a layered approach for maximum maintainability:

- **nxc**: The main CLI entry point.
- **nxc-protocols**: Core network handling for SMB, LDAP, SSH, etc.
- **nxc-auth**: Shared authentication engines (NTLM, Kerberos, Cryptography).
- **nxc-modules**: Post-exploitation module library.
- **nxc-targets**: Advanced target parsing (CIDR, ranges, files).
- **nxc-db**: Credential storage and workspace management.

---

## License & Disclaimer

Distributed under the **BSD 2-Clause License**. See [LICENSE](LICENSE) for more information.

### ⚠️ Legal Disclaimer
**NetExec-RS is for educational purposes and authorized security testing only.** Use of this tool for attacking targets without prior mutual consent is illegal. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
