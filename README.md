# ◈ NetExec-RS (nxc-rs) ◈

[![Release](https://img.shields.io/github/v/release/thrive-spectrexq/nxc-rs?color=blue&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/thrive-spectrexq/nxc-rs/build-binaries.yml?branch=master&style=flat-square)](https://github.com/thrive-spectrexq/nxc-rs/actions)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg?style=flat-square)](LICENSE)

---

## Key Features

*   **Blazing Fast**: Powered by Tokio's async runtime for massive high-concurrency operations.
*   **Pure Rust**: Zero dependencies on Python or Impacket. Native implementation of NTLM SSP, Kerberos, and SMB.
*   **Stealthy & Robust**: Built-in lockout detection, jitter, and secure TLS communication.
*   **Professional Telegram Bot**: Remote mission control with **Interactive Shell**, full module support, and tactical guides.
*   **AI Mission Orchestrator**: Fully autonomous agent powered by **LLMs** for natural language mission control, automated reconnaissance, and tool chaining.
*   **Advanced Recon**: Integrated AD CS, BloodHound, and WMI reconnaissance modules.

---

## Protocols & Capabilities

NetExec-RS supports **18 protocols** and **32 modules** for complete cross-protocol exploitation.

| Protocol | Status | Capabilities |
| :--- | :--- | :--- |
| **SMB** | ✅ Active | **NTLM SSP**, Negotiate/Session, Share/Disk Enum, **smbexec**, lsassy, dcshadow, SAM/LSA/NTDS dumping |
| **LDAP** | ✅ Active | User/Group Enum, **AD CS Enum**, **BloodHound Export**, Roasting, gMSA, **LAPS password reading** |
| **SSH** | ✅ Active | Password & Key Auth, Command Exec, Sudo Check, Fingerprinting |
| **WinRM** | ✅ Active | NTLM/Kerberos Auth, **PSRP Object handling**, Command Exec (PS/CMD) |
| **MSSQL** | ✅ Active | SQL Query, `xp_cmdshell`, **IMPERSONATE privilege checks** |
| **WMI** | ✅ Active | Direct execution, **Process/Service/Patch Enumeration** |
| **ADB** | ✅ Active | Handshake, Shell execution, Screenshotting |
| **RDP** | ✅ Active | NLA authentication, TSRequest generation, Screenshotting |
| **VNC** | ✅ Active | Authentication, Screenshotting |
| **FTP/NFS**| ✅ Active | Directory listing, Export/Share enumeration |
| **HTTP** | ✅ Active | Web reconnaissance, SSL/TLS validation |

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

### 3. Example Execution Commands
Here are a few ways to test the current capabilities (replace `<target>` with a lab IP or CIDR):

**WinRM PSRP Execution**: Run PowerShell commands securely via WinRM.
```powershell
cargo run --package nxc -- winrm <target> -u Admin -p Pass123 -x "Get-Process"
```

**SMB LSA Dumping**: Dump LSA secrets from an entire /24 subnet.
```powershell
cargo run --package nxc -- smb 192.168.1.0/24 -u Admin -H 31d6cfe0d16ae931b73c59d7e0c089c0 -M lsassy
```

**NFS Enumeration**: List exported shares via the MOUNT service.
```powershell
cargo run --package nxc -- nfs <target> --enum-shares
```

**Module Listing**: See which offensive modules are available for a protocol.
```powershell
cargo run --package nxc -- smb <target> -L
```

### 4. Telegram Bot (APEX-REAPER) Integration
NetExec-RS includes a built-in APEX-REAPER Telegram bot for remote management.

**Setup**:
1. Create a bot via [@BotFather](https://t.me/botfather).
2. Add your token to the `.env` file:
   ```env
   TELEGRAM_BOT_TOKEN="your_token_here"
   ```

**Start the Server**:
```powershell
cargo run --package nxc -- telegram
```

**Commands**:
- `/help`, `/guide`, `/cheat`: Comprehensive operator's manuals and search tools.
- `/ai <instruction>`: **Autonomous Mission Control**. Let the AI agent orchestrate discovery, scanning, and exploitation using the full protocol suite.
- `/ping`, `/dns`, `/geo`: Tactical network utilities for rapid connectivity and identity checks.
- `/run <protocol> <target> [options]`: Full CLI-style command execution (supports `-M` and `-o`).
- `/shell`: Activate **Interactive Shell Mode** for the most recent target.
- `/shares`, `/users`, `/groups`: Tactical reconnaissance shortcuts.
- `/clear`, `/reset`: Flush session memory and clear terminal space.

### 5. AI Mission Control (CLI)
The **Elite Reaper** AI orchestrator can be launched directly from the CLI for autonomous missions. It supports conversational multi-turn interaction.

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

### 6. Build for Production
If you want to use the compiled binary directly without `cargo run`, you can build a release version:
```powershell
cargo build --release --package nxc
```
The binary will be located at `target\release\nxc.exe` (Windows) or `target/release/nxc` (Linux).

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

Distributed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for more information.

### Legal Disclaimer
**NetExec-RS is for educational purposes and authorized security testing only.** Use of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
