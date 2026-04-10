# Welcome to the NetExec-RS Wiki

Welcome to the **NetExec-RS (nxc-rs)** documentation. As of v0.4.0, NetExec-RS is the most capable, high-performance, and feature-rich offensive orchestration frameworks available, built entirely in asynchronous Rust.

## What is NetExec-RS?

NetExec-RS is a brutal, monolithic network exploitation and administrative orchestration tool. Originally designed as a high-performance alternative to Python-based NetExec (CrackMapExec), `nxc-rs` has fundamentally evolved past its origins. 

It currently supports:
* **22 distinct network protocols** (SMB, LDAP, MSSQL, DNS, IPMI, Kubernetes, RDP, WinRM, etc.)
* **135 specialized modules** for post-exploitation, enumeration, credential harvesting, and evasion.
* **Autonomous AI Agents** built-in for conversational mission control.


## Quick Navigation

### 🛠️ Getting Started
* [Installation Guide](Installation.md)
* [Core Architecture & Design](Core-Architecture.md)

### 📚 Protocol Reference 
*(How to authenticate and interact with specific services)*
* [SMB & Core Windows](Protocols/SMB-Protocol.md) *(Coming Soon)*
* [DNS Enumeration](Protocols/DNS-Protocol.md)
* [IPMI & BMCs](Protocols/IPMI-Protocol.md)
* [iLO & iDRAC Redfish](Protocols/iLO-iDRAC-Protocol.md)
* [Kubernetes API](Protocols/Kubernetes-Protocol.md)

### 🧰 Module Catalogs 
*(Post-exploitation capabilities)*
* [SMB / AD Core Modules](Modules/SMB-AD-Core.md): Credentials, GPP, Spooler, EDR detection.
* [LDAP Enumeration](Modules/LDAP-Enumeration.md): DACLs, RBCD, BloodHound, LAPS.
* [MSSQL Offensive](Modules/Modules/MSSQL-Offensive.md): Querying, `xp_cmdshell`, Link execution.
* [Credential Harvesting](Modules/Credential-Harvesting.md): Firefox, WinSCP, KeePass, Veaam.
* [Persistence & Lateral Movement](Modules/Persistence-Lateral-Movement.md): LNK droppers, Empire, Web Delivery.
* [Rust-Exclusive Advanced](Modules/RS-Exclusive-Advanced.md): AMSI bypass, ETW patching, BOF loaders.

### 🤖 Advanced Operations
* [Elite Reaper AI Orchestrator](AI-Orchestrator-Guide.md)


---
> [!IMPORTANT]
> **Legal Disclaimer:** NetExec-RS is for educational and authorized professional security testing only. Use against networks without prior mutual consent is illegal. The developers assume no liability for misuse.
