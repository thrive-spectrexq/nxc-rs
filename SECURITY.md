# Security Policy

## Supported Versions

We only support the latest version of NetExec-RS. For older versions, we recommend upgrading to the latest release for security updates.

| Version | Supported          |
| ------- | ------------------ |
| v0.4.x  | :white_check_mark: |
| v0.3.x  | :x:                |
| < v0.3  | :x:                |

## Reporting a Vulnerability

We take security seriously at NetExec-RS. If you discover a security vulnerability in this project, please report it privately.

**Do not report security vulnerabilities in public GitHub issues.**

Please send security reports via:
- GitHub Security Advisories: [Private Report](https://github.com/thrive-spectrexq/nxc-rs/security/advisories/new)

Please include the following information in your report:
- A detailed description of the vulnerability.
- Steps to reproduce the issue.
- Potential impact and mitigation strategies.

We will respond within 48 hours, and work with you to resolve the issue as quickly as possible.

## Supply Chain & License Compliance

### SBOM (Software Bill of Materials)
Starting with version `0.4.x`, every GitHub Release includes a standard CycloneDX JSON SBOM (`nxc-rs-sbom.json`). This file contains the complete cryptographic hashes, versions, and origins of all compiled dependencies for supply chain verification.

### License Auditing & Dual-License Scenarios
We strictly audit dependencies using `cargo-deny` in our CI pipeline (`deny.toml`). 
- Only OSI-approved permissive licenses (MIT, Apache-2.0, BSD, etc.) are allowed.
- For **dual-licensed** dependencies (e.g., `MIT OR Apache-2.0`), `cargo-deny` automatically evaluates the expression. We guarantee that the resulting compiled binary complies with a permissive license subset, making it safe for organizational and commercial usage.

## Threat Model & Cryptographic Specifications

### Threat Model
NetExec-RS operates in hostile enterprise environments and processes untrusted network data. Our primary threat model assumes:
1. **Malicious Target Servers**: A target server may attempt to exploit the tool by returning malformed binary structures (e.g., manipulated NTLM challenges, malicious Kerberos tickets, or infinite DCE/RPC loops).
2. **Credential Isolation**: Credentials loaded into the engine must be securely isolated per session. They will not bleed between concurrent protocol workers or tasks.
3. **Log Sanitization**: Logs and output files must aggressively sanitize control characters and unicode homoglyphs to prevent terminal injection, CSV injection, and HTML injection.

### Cryptographic Infrastructure
NetExec-RS relies on robust Rust-native cryptographic implementations:
- **TLS/SSL**: All connections mandate a minimum of `TLS 1.2`. `rustls` is prioritized where available for native Certificate Transparency (CT) log validation and OCSP stapling.
- **Hash Functions**: We utilize `rust-crypto` (via `md-5`, `sha2`, `hmac`) for NTLM and Kerberos crypto. Algorithms that are cryptographically broken (like MD4/MD5) are **only** implemented for backwards-compatibility required by legacy Windows authentication protocols (NTLMv1/v2).

## Ethical Research

Please ensure your security research follows ethical guidelines and legal requirements. Avoid any actions that could harm the community or compromise user data.

Thank you for helping us keep NetExec-RS secure!
