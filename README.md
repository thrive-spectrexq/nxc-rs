# ◈ NetExec-RS (nxc-rs) ◈

[![Rust](https://img.shields.io/badge/rustc-1.94.0+-orange.svg?style=flat-square)](https://www.rust-lang.org/)
[![Release](https://img.shields.io/github/v/release/thrive-spectrexq/nxc-rs?color=blue&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/thrive-spectrexq/nxc-rs/build-binaries.yml?branch=master&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/actions)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg?style=flat-square)](LICENSE)

---

**NetExec-RS (nxc-rs)** is a modern, high-performance network execution tool built in Rust. Inspired by Pennyw0rth [NetExec](https://github.com/Pennyw0rth/NetExec.git), it brings blazing-fast concurrency, memory safety, and native protocol implementations to the modern red-teaming toolkit.

## 🚀 Key Features

*   **Blazing Performance**: Engineered with Tokio's async runtime for massive concurrency across large-scale networks.
*   **Pure Rust Core**: Zero Python or Impacket dependencies. Native, safe implementations of NTLM SSP, Kerberos, and SMB.
*   **AI Mission Orchestrator**: Control missions with natural language via the **Elite Reaper** AI engine (Gemini, OpenAI, Anthropic, or Ollama).
*   **Stealth & Resilience**: Built-in lockout protection, configurable jitter, random delays, and secure TLS handling.
*   **Advanced Reconnaissance**: Native AD CS enumeration, BloodHound integration, WMI recon, and more.

---

## 🛠 Protocols & Capabilities

`nxc-rs` supports **22 protocols** and **135+ offensive modules**, all optimized for speed and reliability.

| Protocol | Status | Highlights |
| :--- | :--- | :--- |
| **SMB** | ✅ | NTLM SSP, Shares, smbexec, lsassy, DCShadow, NTDS dumping |
| **LDAP** | ✅ | AD CS, BloodHound, gMSA/LAPS enum, Roasting |
| **WinRM** | ✅ | NTLM/Kerberos auth, PSRP command execution |
| **MSSQL** | ✅ | Queries, xp_cmdshell, impersonation checks |
| **WMI** | ✅ | System enumeration and command execution |
| **SSH** | ✅ | Auth auditing, exec, and sudo verification |
| **ADB/RDP/VNC** | ✅ | Shell access and automated screenshots |
| **Web/DNS/FTP** | ✅ | High-speed reconnaissance and enumeration |
| **Cloud/Kube** | ✅ | Redfish probing, Kubernetes cluster enumeration |

---

## 📦 Installation

### Quick Install (Recommended)

**Linux / macOS:**
```bash
curl -sSf https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.sh | bash
```

**Windows (PowerShell):**
```powershell
iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.ps1')
```

### From Source

Requires `rustc 1.94.0` or newer.

```bash
git clone https://github.com/thrive-spectrexq/nxc-rs.git
cd nxc-rs
cargo build --release --package nxc
```

---

## Usage & Examples

### Getting Help
To see all available protocols and global options:
```bash
nxc --help
```

To see protocol-specific flags (e.g., SMB or WinRM):
```bash
nxc smb --help
nxc winrm --help
```

### Command Examples

**WinRM PSRP Execution:**
```powershell
nxc winrm <target> -u Admin -p Pass123 -x "Get-Process"
```

**SMB LSA Dumping (lsassy):**
```powershell
nxc smb 192.168.1.0/24 -u Admin -H <hash> -M lsassy
```

**NFS Share Enumeration:**
```powershell
nxc nfs <target> --enum-shares
```

---

## AI Mission Control

The **Elite Reaper** allows you to orchestrate complex attacks using natural language.

### Setup
Set one of the following environment variables:
*   `GEMINI_API_KEY` (Default)
*   `OPENAI_API_KEY`
*   `ANTHROPIC_API_KEY`
*   `OLLAMA_API_BASE`

### Examples
Launch an interactive mission directly from your terminal:
```bash
nxc ai "Scan 10.0.0.0/24 for port 445 and identify OS versions"
nxc ai "Enumerate all GPO names from the domain using ldap"
nxc ai "Find hosts with SMB signing disabled on 192.168.1.0/24"
```

---

## Architecture

The project is structured as a modular workspace for maximum maintainability:

*   **[`nxc`](nxc-rs/nxc)**: Main CLI entry point and orchestration layer.
*   **[`nxc-protocols`](nxc-rs/protocols)**: Core network handling (SMB, LDAP, SSH, etc.).
*   **[`nxc-auth`](nxc-rs/auth)**: Unified authentication engine (NTLM, Kerberos).
*   **[`nxc-ai`](nxc-rs/ai)**: The Elite Reaper LLM orchestration engine.
*   **[`nxc-modules`](nxc-rs/modules)**: Post-exploitation and reconnaissance modules.
*   **[`nxc-db`](nxc-rs/db)**: SQLite-backed credential and workspace management.

---

## License & Disclaimer

Distributed under the **BSD 2-Clause License**. See [LICENSE](LICENSE) for details.

### ⚠️ Legal Disclaimer
**NetExec-RS is for authorized security testing and educational purposes only.** Use of this tool against targets without prior mutual consent is illegal. The developers assume no liability for misuse or damage caused by this program.
