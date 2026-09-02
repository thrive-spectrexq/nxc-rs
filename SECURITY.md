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
- **GitHub Security Advisories (Preferred)**: [Private Vulnerability Report](https://github.com/thrive-spectrexq/nxc-rs/security/advisories/new)
- **Direct Security Contact**: `security@netexec-rs.org` (or encrypted communication via maintainer PGP keys listed on GitHub)

Please include the following information in your report:
- A detailed description of the vulnerability and affected components.
- Complete steps or proof-of-concept (PoC) to reproduce the issue safely.
- Potential impact, attack vector, and mitigation suggestions.

### Vulnerability Response Timeline & SLA
- **Initial Acknowledgment**: Within 48 hours of receipt.
- **Triage & Severity Assessment (CVSS v3.1)**: Within 5 business days.
- **Patch Development & Testing**: Critical (within 14 days), High (within 21 days), Medium/Low (within 30 days).
- **Release & Coordinated Disclosure**: 30–60 days from initial report, or coordinated mutually with the reporter.

### CVE Assignment Process
NetExec-RS follows the CVE Program guidelines through GitHub Security Advisories (GHSA):
1. Upon confirming a vulnerability in core components (especially cryptographic implementations, protocol parsers, authentication modules, or execution isolation), a GHSA draft is created.
2. Maintainers request a CVE ID directly through GitHub's CNA partnership.
3. Fixes are developed in private forks and reviewed before public release.
4. The CVE advisory is published simultaneously with the patched release tag.

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
1. **Malicious Target Servers**: A target server may attempt to exploit the tool by returning malformed binary structures (e.g., manipulated NTLM challenges, malicious Kerberos tickets, or infinite DCE/RPC loops). All parsers must enforce strict bounds-checking and avoid panics.
2. **Credential Isolation & In-Memory Protection**: Credentials loaded into the engine (`Credentials`, `CertificateAuth`, NTLM session keys) must be securely isolated per session. They will not bleed between concurrent protocol workers or tasks, and must implement `Zeroize` on drop to scrub memory.
3. **Database Security at Rest**: When credentials and host metadata are stored in `nxc.db`, the database must reside in directories protected with restrictive filesystem permissions (POSIX `0700`/`0600` on Linux/macOS; restricted owner-only DACLs on Windows). For sensitive engagements, users are advised to place the database on an encrypted filesystem volume (BitLocker, LUKS, or FileVault) or configure SQLCipher.
4. **Log & Prompt Sanitization**: Logs and output files must aggressively sanitize control characters, unicode homoglyphs, and redact API keys and passwords. AI provider completions must redact authentication tokens from prompts, responses, and error traces.

### Cryptographic Infrastructure
NetExec-RS relies on robust Rust-native cryptographic implementations:
- **Constant-Time Verification**: All cryptographic message authentication codes (HMAC-MD5, HMAC-SHA1-96 in Kerberos, NTLM response signatures) enforce constant-time equality comparisons to prevent timing side-channel attacks.
- **Memory Scrubbing**: Sensitive keys, plaintext passwords, private keys, and intermediate hash states are wrapped in types implementing `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop`.
- **TLS/SSL**: All connections mandate a minimum of `TLS 1.2`. `rustls` is prioritized where available for native Certificate Transparency (CT) log validation and OCSP stapling.
- **Legacy Compatibility**: Cryptographically weak algorithms (MD4, MD5, RC4, DES) are **strictly isolated** to protocol-mandated legacy Windows compatibility (NTLMv1/v2, Kerberos RC4-HMAC, Kerberos DES). They are never used for general security operations or new features.

## Ethical Research

Please ensure your security research follows ethical guidelines and legal requirements. Avoid any actions that could harm the community or compromise user data.

Thank you for helping us keep NetExec-RS secure!

