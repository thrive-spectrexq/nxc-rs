# ◈ NetExec-RS (nxc-rs) ◈

[![Rust](https://img.shields.io/badge/rustc-1.88.0+-orange.svg?style=flat-square)](https://www.rust-lang.org/)
[![Release](https://img.shields.io/github/v/release/thrive-spectrexq/nxc-rs?color=blue&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/thrive-spectrexq/nxc-rs/build-binaries.yml?branch=master&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/actions)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg?style=flat-square)](LICENSE)

High-Performance Network Execution Framework (Rust)

NetExec-RS (nxc-rs) is a high-performance network execution framework built in Rust, designed for modern red team operations at scale.

Inspired by NetExec and CrackMapExec, nxc-rs reimagines network exploitation with:

- massive concurrency
- intelligent orchestration
- memory-safe native implementations

## Why nxc-rs?

Traditional tooling in this space is:

- Python-heavy
- dependency-fragile
- slow at scale

nxc-rs changes that:

- Pure Rust core → zero runtime dependencies
- Async-first architecture → scan and execute across thousands of hosts
- Protocol-native implementations → no wrappers, no overhead
- Designed for automation → integrates seamlessly into pipelines and AI workflows

## Key Features

### Performance & Reliability
- Tokio-powered async runtime for extreme concurrency
- Optimized for large enterprise network operations
- Low memory footprint with predictable performance

### Native Rust Core
- No Python, no Impacket
- Native implementations of:
  - NTLM SSP
  - Kerberos
  - SMB protocol stack

### AI Mission Orchestrator
- Built-in Elite Reaper engine
- Control operations using natural language
- Supports:
  - Gemini
  - OpenAI
  - Anthropic
  - Ollama

### Stealth & Evasion
- Lockout-aware authentication strategies
- Configurable jitter and randomized delays
- Secure TLS handling
- Reduced detection footprint

### Advanced Reconnaissance
- Active Directory enumeration (LDAP, AD CS)
- BloodHound data collection
- WMI-based system intelligence
- Credential and privilege discovery

## Protocols & Capabilities

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

## Installation

### Quick Install

**Linux / macOS**
```bash
curl -sSf https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.sh | bash
```

**Windows (PowerShell)**
```powershell
iex (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/thrive-spectrexq/nxc-rs/master/install.ps1')
```

### Build from Source

Requires Rust 1.88.0+

```bash
git clone https://github.com/thrive-spectrexq/nxc-rs.git
cd nxc-rs
cargo build --release --package nxc
```

## Quickstart

### Linux & macOS Quickstart

```bash
# 1. Inspect target subnet over SMB
nxc smb 192.168.1.0/24

# 2. Authenticate with credentials and list shares
nxc smb 192.168.1.50 -u Administrator -p 'P@ssw0rd123!' --shares

# 3. Authenticate with NTLM hash
nxc smb 192.168.1.50 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# 4. Execute command via WinRM
nxc winrm 192.168.1.50 -u Administrator -p 'P@ssw0rd123!' -x "whoami /all"

# 5. Output JSON for pipeline consumption
nxc smb 192.168.1.0/24 --json | jq .
```

### Windows (PowerShell) Quickstart

```powershell
# 1. Sweep local network for SMB services
nxc.exe smb 10.0.0.0/24

# 2. Query Active Directory LDAP users
nxc.exe ldap 10.0.0.5 -u "CORP\audit" -p "Audit2026!" --users

# 3. Run Kerberoasting against Domain Controller
nxc.exe ldap 10.0.0.5 -u "CORP\audit" -p "Audit2026!" --kerberoasting

# 4. Scripted execution with non-interactive confirmation
nxc.exe smb 10.0.0.50 -u Admin -p Pass123 --insecure --non-interactive
```

## Development Guide

### Prerequisites
- Rust stable (1.88+) installed via `rustup`.
- On Linux (Debian/Ubuntu), install native development libraries:
  ```bash
  sudo apt-get update && sudo apt-get install -y libkrb5-dev libsasl2-dev libldap2-dev pkg-config libssl-dev
  ```

### Running Tests
Run the entire workspace test suite:
```bash
cargo test --workspace
```

Run tests for a single crate:
```bash
cargo test -p nxc-auth
cargo test -p nxc-protocols
cargo test -p nxc-ai
```

Run a specific unit test by name:
```bash
cargo test -p nxc-auth test_ntlm_v2_hash
```

### Code Quality & Lints
Format check and static analysis:
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets
```

Dependency security and license auditing:
```bash
cargo deny check
cargo audit
```

## Usage

### Help & Discovery
```bash
nxc --help
```

Protocol-specific help:
```bash
nxc smb --help
nxc winrm --help
nxc ldap --help
```

### Automation & Pipeline Integration
All commands support structured JSON and non-interactive scripted modes for CI/CD or security pipelines:
```bash
# Machine-readable output with zero interactive prompts
nxc smb 10.0.0.0/24 --json --non-interactive > results.json

# Stream logs with structured tracing
nxc winrm 10.0.0.50 -u Admin -p Pass123 -x "hostname" --log run.log --json-log
```

### AI Mission Control (Elite Reaper)

Control operations using natural language.

#### Setup

Configure your preferred LLM provider in `.env` or via environment variables:

```bash
export GEMINI_API_KEY="..."
# or export OPENAI_API_KEY="..."
# or export ANTHROPIC_API_KEY="..."
# or export OLLAMA_API_BASE="http://localhost:11434"
```

#### Examples
```bash
# Safe plan generation (dry-run mode)
nxc ai "Scan 10.0.0.0/24 for SMB and plan domain enumeration" --dry-run

# Active execution requires explicit confirmation flag
nxc ai "Audit SMB shares and extract domain users" --confirm-ai-exec
```

## Architecture

nxc-rs is built as a modular Rust workspace:

- `/nxc` → CLI application + orchestrator
- `/protocols` → SMB, LDAP, SSH, WinRM, MSSQL, RDP, etc.
- `/auth` → Pure-Rust NTLM, Kerberos v5, PKINIT, certificate engine
- `/ai` → Mission control, tool registry, and prompt safety guardrails
- `/modules` → Reconnaissance & post-exploitation modules
- `/db` → SQLite workspace storage
- `/resilience` → Circuit breakers, jitter, and rate limiting
- `/reporting` → Multi-format reporting engine

For in-depth architecture and threat model diagrams, consult:
- [Architecture Guide](docs/architecture.md)
- [Threat Model & Cryptographic Specifications](docs/threat_model.md)

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for our PR checklist, commit guidelines, and coding standards.

## License

Licensed under the BSD 2-Clause License.
See [LICENSE](LICENSE) for details.

## ⚠️ Legal Disclaimer & Acceptable Use Policy

**FOR AUTHORIZED PROFESSIONAL USE ONLY.**

NetExec-RS (`nxc-rs`) is a network execution and penetration testing framework developed specifically for authorized security assessments, vulnerability research, and penetration testing within environments where explicit, documented authorization has been granted.

- **Explicit Authorization Required**: Operating NetExec-RS against networks, devices, or systems without prior written consent from the target infrastructure owner is strictly illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and international computer crime statutes.
- **Limitation of Liability**: The developers and contributors of NetExec-RS assume no liability and are not responsible for any misuse, damage, data loss, or legal consequences resulting from the use of this software.
- **Compliance**: It is the end user's sole responsibility to comply with all applicable local, national, and international laws and organizational rules of engagement before executing any modules or protocol handlers.
