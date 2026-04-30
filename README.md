# ◈ NetExec-RS (nxc-rs) ◈

[![Rust](https://img.shields.io/badge/rustc-1.94.0+-orange.svg?style=flat-square)](https://www.rust-lang.org/)
[![Release](https://img.shields.io/github/v/release/thrive-spectrexq/nxc-rs?color=blue&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/thrive-spectrexq/nxc-rs/build-binaries.yml?branch=master&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/actions)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg?style=flat-square)](LICENSE)

⚡ High-Performance Network Execution Framework (Rust)

NetExec-RS (nxc-rs) is a high-performance network execution framework built in Rust, designed for modern red team operations at scale.

Inspired by CrackMapExec and NetExec, nxc-rs reimagines network exploitation with:

- massive concurrency
- intelligent orchestration
- memory-safe native implementations

This is not just a rewrite — it’s a next-generation execution engine built for speed, stealth, and extensibility.

## 🚀 Why nxc-rs?

Traditional tooling in this space is:

- Python-heavy
- dependency-fragile
- slow at scale

nxc-rs changes that:

- Pure Rust core → zero runtime dependencies
- Async-first architecture → scan and execute across thousands of hosts
- Protocol-native implementations → no wrappers, no overhead
- Designed for automation → integrates seamlessly into pipelines and AI workflows

## 🔥 Key Features

### ⚡ Performance & Reliability
- Tokio-powered async runtime for extreme concurrency
- Optimized for large enterprise network operations
- Low memory footprint with predictable performance

### 🧱 Native Rust Core
- No Python, no Impacket
- Native implementations of:
  - NTLM SSP
  - Kerberos
  - SMB protocol stack

### 🤖 AI Mission Orchestrator
- Built-in Elite Reaper engine
- Control operations using natural language
- Supports:
  - Gemini
  - OpenAI
  - Anthropic
  - Ollama

### 🥷 Stealth & Evasion
- Lockout-aware authentication strategies
- Configurable jitter and randomized delays
- Secure TLS handling
- Reduced detection footprint

### 🔎 Advanced Reconnaissance
- Active Directory enumeration (LDAP, AD CS)
- BloodHound data collection
- WMI-based system intelligence
- Credential and privilege discovery

## 📡 Protocols & Capabilities

nxc-rs supports 22 protocols and 135+ modules, built for both reconnaissance and post-exploitation.

| Protocol | Status | Capabilities |
| :--- | :--- | :--- |
| **SMB** | ✅ | NTLM auth, shares, smbexec, lsassy, NTDS dumping |
| **LDAP** | ✅ | AD CS, BloodHound, LAPS/gMSA, Kerberoasting |
| **WinRM** | ✅ | NTLM/Kerberos, PSRP execution |
| **MSSQL** | ✅ | Query execution, xp_cmdshell, impersonation |
| **WMI** | ✅ | Remote execution & system enumeration |
| **SSH** | ✅ | Auth auditing, command execution |
| **RDP / VNC / ADB** | ✅ | Remote access, screenshots |
| **Web / DNS / FTP** | ✅ | Enumeration & recon |
| **Cloud / Kube** | ✅ | Kubernetes & infrastructure probing |

## 📦 Installation

### ⚡ Quick Install

**Linux / macOS**
```bash
curl -sSf https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.sh | bash
```

**Windows (PowerShell)**
```powershell
iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.ps1')
```

### 🛠 Build from Source

Requires Rust 1.94.0+

```bash
git clone https://github.com/thrive-spectrexq/nxc-rs.git
cd nxc-rs
cargo build --release --package nxc
```

## 📖 Usage

### Help & Discovery
```bash
nxc --help
```

Protocol-specific help:
```bash
nxc smb --help
nxc winrm --help
```

### Examples

**WinRM Command Execution**
```bash
nxc winrm <target> -u Admin -p Pass123 -x "Get-Process"
```

**SMB Credential Dumping**
```bash
nxc smb 192.168.1.0/24 -u Admin -H <hash> -M lsassy
```

**NFS Enumeration**
```bash
nxc nfs <target> --enum-shares
```

### AI Mission Control (Elite Reaper)

Control operations using natural language.

#### ⚙️ Setup

Set one provider:

```bash
export GEMINI_API_KEY=...
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
export OLLAMA_API_BASE=...
```

#### 💡 Examples
```bash
nxc ai "Scan 10.0.0.0/24 for port 445 and identify OS versions"
nxc ai "Enumerate all GPO names using LDAP"
nxc ai "Find hosts with SMB signing disabled"
```

## 🏗 Architecture

nxc-rs is built as a modular Rust workspace:

- `/nxc` → CLI + orchestration
- `/protocols` → SMB, LDAP, SSH, etc.
- `/auth` → NTLM, Kerberos engine
- `/ai` → Elite Reaper AI engine
- `/modules` → Recon & post-exploitation modules
- `/db` → Credential storage (SQLite)

### Design Principles
- Modular & extensible
- Async-first
- Protocol-driven architecture
- Clean separation of concerns

## 🗺️ Roadmap
- Plugin / external module system
- Distributed execution (multi-node ops)
- Advanced evasion techniques
- Web UI / dashboard
- Blue-team simulation mode

## 🤝 Contributing

Contributions are welcome.

1. Fork the repo
2. Create a feature branch
3. Submit a PR

For major changes, open an issue first.

## 📄 License

Licensed under the BSD 2-Clause License.
See [LICENSE](LICENSE) for details.

## ⚠️ Legal Disclaimer

This tool is intended strictly for authorized security testing and educational purposes.

- Unauthorized use against systems without explicit permission is illegal.
- The authors are not responsible for misuse or damages.