# ◈ NetExec-RS (nxc-rs) ◈

[![CI](https://github.com/thrive-spectrexq/nxc-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/thrive-spectrexq/nxc-rs/actions)
[![Rust Version](https://img.shields.io/badge/rust-1.94.0%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/thrive-spectrexq/nxc-rs)](https://github.com/thrive-spectrexq/nxc-rs/releases)

**NetExec-RS** is a high-performance, pure Rust reimplementation of the legendary [NetExec](https://github.com/Pennyw0rth/NetExec). It is a "Swiss army knife" for network assessment, designed for penetration testers and red teamers to automate credential spraying, service enumeration, and post-exploitation across multiple protocols.

---

## 🚀 Key Features

*   **⚡ Blazing Fast**: Powered by Tokio's async runtime for massive concurrency.
*   **🦀 Pure Rust**: Zero dependencies on Python, Impacket, or external binaries. Native implementation of NTLM, Kerberos, and SMB.
*   **🛡️ Stealthy & Robust**: Built-in lockout detection and jitter to bypass defensive monitoring.
*   **🔌 Multi-Protocol**: Native support for **SMB, SSH, LDAP, WinRM, MSSQL, FTP, and NFS**.
*   **📦 Module System**: Extensible architecture supporting post-exploitation modules like `secretsdump`, `laps`, and more.

---

## 🛠️ Protocols & Capabilities

| Protocol | Status | Capabilities |
| :--- | :--- | :--- |
| **SMB** | ✅ Active | Auth, Share Enum, Disk Enum, Session Enum, Command Exec (WMI/SMBExec), `secretsdump` |
| **LDAP** | ✅ Active | User/Group Enum, Kerberoasting, ASREProasting, gMSA password dumping |
| **SSH** | ✅ Active | Password & Key Auth, Command Execution, Sudo Check |
| **WinRM** | ✅ Active | NTLM/Kerberos Auth, Command Execution (PowerShell/CMD) |
| **MSSQL** | ✅ Active | SQL Query execution, `xp_cmdshell` execution |
| **FTP** | ✅ Active | Real authentication, Directory listing (`ls`) |
| **NFS** | ✅ Active | Export/Share enumeration via MOUNT RPC |
| **RDP** | 🚧 Impl | NLA authentication, Screenshotting |
| **WMI** | 🚧 Impl | Direct WMI execution |
| **VNC** | 🚧 Impl | Screenshotting |

---

## 📦 Installation & Setup

### Prerequisites
- [Rust Toolchain](https://rustup.rs/) (v1.94.0+)

### Building from Source
```bash
# Clone the repository
git clone https://github.com/thrive-spectrexq/nxc-rs.git
cd nxc-rs

# Build all workspace packages
cargo build --workspace
```

---

## 💻 Local Development

### 1. View Global Help
```bash
cargo run --package nxc -- --help
```

### 2. Protocol-Specific Help
```bash
# Get help for a specific protocol (e.g., SMB)
cargo run --package nxc -- smb --help
```

### 3. Quick Start Examples
```powershell
# SMB Share Enumeration
cargo run --package nxc -- smb 192.168.1.0/24 -u admin -p 'Password123' --shares

# LDAP Kerberoasting
cargo run --package nxc -- ldap dc01.corp.local -u user -p pass --kerberoasting

# FTP File Listing
cargo run --package nxc -- ftp 192.168.1.50 -u anonymous -p anonymous --ls

# NFS Share Listing
cargo run --package nxc -- nfs 192.168.1.60 --enum-shares
```

---

## 🏗️ Architecture

NetExec-RS is designed with a layered approach for maximum maintainability:

- **nxc**: The main CLI entry point.
- **nxc-protocols**: Core network handling for SMB, LDAP, SSH, etc.
- **nxc-auth**: Shared authentication engines (NTLM, Kerberos, Cryptography).
- **nxc-modules**: Post-exploitation module library.
- **nxc-targets**: Advanced target parsing (CIDR, ranges, files).
- **nxc-db**: Credential storage and workspace management (work in progress).

---

## 🗺️ Roadmap

- [ ] Support for RDP screenshots.
- [ ] Integration of a centralized SQLite database (`nxcdb` parity).
- [ ] BloodHound (SharpHound) compatible ingestion module.
- [ ] More execution methods (DCOM, Task Scheduler).
- [ ] Interactive shell mode.

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License & Disclaimer

Distributed under the MIT License. See `LICENSE` for more information.

### Legal Disclaimer
**NetExec-RS is for authorized security testing only.** Use of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
