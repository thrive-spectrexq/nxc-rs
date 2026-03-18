# ◈ NetExec-RS (nxc-rs) ◈

[![CI](https://github.com/thrive-spectrexq/nxc-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/thrive-spectrexq/nxc-rs/actions)
[![Rust Version](https://img.shields.io/badge/rust-1.94.0%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Custom-orange.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/thrive-spectrexq/nxc-rs)](https://github.com/thrive-spectrexq/nxc-rs/releases)

**NetExec-RS** is a high-performance, pure Rust reimplementation of the legendary [NetExec](https://github.com/Pennyw0rth/NetExec). It is a "Swiss army knife" for network assessment, designed for penetration testers and red teamers to automate credential spraying, service enumeration, and post-exploitation across multiple protocols.

---

## Key Features

*   **Blazing Fast**: Powered by Tokio's async runtime for massive high-concurrency operations.
*   **Pure Rust**: Zero dependencies on Python or Impacket. Native implementation of NTLM SSP, Kerberos, and SMB.
*   **Stealthy & Robust**: Built-in lockout detection, jitter, and secure TLS communication.
*   **Professional Telegram Bot**: Remote mission control with **Interactive Shell**, full module support, and tactical guides.
*   **Advanced Recon**: Integrated AD CS, BloodHound, and WMI reconnaissance modules.

---

## Protocols & Capabilities

| Protocol | Status | Capabilities |
| :--- | :--- | :--- |
| **SMB** | ✅ Active | **NTLM SSP**, Share/Disk Enum, **smbexec (SVCCTL)**, `secretsdump` skeleton |
| **LDAP** | ✅ Active | User/Group Enum, **AD CS Enum**, **BloodHound Export**, Roasting, gMSA |
| **SSH** | ✅ Active | Password & Key Auth, Command Exec, Sudo Check, Fingerprinting |
| **WinRM** | ✅ Active | NTLM/Kerberos Auth, **PSRP Object handling**, Command Exec (PS/CMD) |
| **MSSQL** | ✅ Active | SQL Query, `xp_cmdshell`, **IMPERSONATE privilege checks** |
| **WMI** | ✅ Active | Direct execution, **Process/Service/Patch Enumeration** |
| **ADB** | ✅ Active | Handshake, Shell execution, Screenshotting |
| **RDP** | ✅ Active | NLA authentication, Screenshotting |
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

# NFS Help
cargo run --package nxc -- nfs --help
```

### 3. Example Execution Commands
Here are a few ways to test the current capabilities (replace `<target>` with a lab IP or CIDR):

**ADB Execution**: Run commands directly on Android devices with exposed debugging ports (TCP 5555).
```powershell
cargo run --package nxc -- adb <target> -x "getprop ro.build.version.release"
```

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

### 4. Telegram Bot Integration
NetExec-RS includes a built-in Telegram bot for remote management.

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
- `/run <protocol> <target> [options]`: Full CLI-style command execution (supports `-M` and `-o`).
- `/shell`: Activate **Interactive Shell Mode** for the most recent target.
- `/shares`, `/users`, `/groups`: Tactical reconnaissance shortcuts.

### 5. Build for Production
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
- **nxc-db**: Credential storage and workspace management (work in progress).

---

## License & Disclaimer

Distributed under a Custom Proprietary License. See `LICENSE` for more information.

### Legal Disclaimer
**NetExec-RS is for authorized security testing only.** Use of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
