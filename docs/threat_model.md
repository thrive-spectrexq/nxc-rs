# NetExec-RS Threat Model & Cryptographic Specification

## 1. Executive Summary & Scope

NetExec-RS (`nxc-rs`) is a network execution and security evaluation framework designed for enterprise penetration testing, red teaming, and Active Directory security auditing. By nature of its operation, NetExec-RS handles sensitive enterprise assets, including:
- Cleartext administrative passwords
- NTLM hashes (NT / LM)
- Kerberos tickets (TGT / TGS) and Kerberos AES/RC4 keys
- Active Directory schemas and enumeration metadata
- Machine accounts, gMSA passwords, and LSA secrets
- AI Provider API keys (OpenAI, Anthropic, Gemini, Ollama)

This document formally specifies the threat model, security boundaries, cryptographic protections, memory lifecycle, and database persistence standards enforced by NetExec-RS.

---

## 2. Threat Actors & Attack Boundaries

| Boundary | Threat Vector | Mitigation in NetExec-RS |
|---|---|---|
| **Target Server to Client** | Malicious or compromised targets returning malformed ASN.1, corrupt DCE/RPC packets, or oversized SMB headers to induce memory corruption or panics. | Pure Rust protocol parsers with bounds-checked slices (`nom`, `rasn`, standard byte deserializers) with zero unsafe code (`#![forbid(unsafe_code)]`). |
| **Local Memory (RAM)** | Unauthorized memory scraping, core dumps, or debugger inspection extracting cleartext passwords and keys after drop. | Sensitive structures implement `zeroize::Zeroize` and `#[zeroize(drop)]`. Memory buffers holding keys and cleartext passwords are zeroized immediately when they go out of scope. |
| **Storage at Rest (`nxc.db`)** | Unauthorized local users accessing the SQLite workspace database containing harvested hashes and passwords. | Stored files enforce restrictive file permissions (POSIX `0600` / `0700` on Unix; owner-restricted DACLs on Windows). Recommended deployment on encrypted volumes (BitLocker / LUKS). |
| **Network Eavesdropping** | Interception of administrative sessions, Kerberos pre-auth blobs, or LDAP queries. | Mandatory TLS 1.2+ minimum with certificate validation enabled by default. Channel binding tokens (EPA) supported on NTLM and LDAPS. Insecure overrides require explicit confirmation or `--non-interactive`. |
| **Log & Report Leaks** | Credentials, API keys, or private keys leaking into CLI output, machine logs, or exported reports. | Redaction applied across all logging macros (`tracing`). Display implementations for `Credentials` omit passwords/hashes. AI providers redact API keys in `Debug` output and API error messages. |
| **Side-Channel Timing Attacks** | Exploitation of non-constant-time equality checks during HMAC verification in Kerberos or NTLM responses. | Constant-time comparison primitives (`subtle::ConstantTimeEq` or constant-time byte comparisons) enforced for all MAC and signature verifications. |
| **Prompt Injection (AI Engine)** | Malicious hostnames or banner text manipulating LLM reasoning to execute destructive actions. | Input sanitization, strict tool allow-listing, prompt escaping, optional dry-run mode, and mandatory `--confirm-ai-exec` confirmation for active tools. |

---

## 3. Cryptographic Lifecycle & Memory Zeroization

### 3.1 Memory Protection via Zeroize
All cryptographic credentials implement the `zeroize` trait:
- [`Credentials`](file:///C:/Users/frimp/Documents/nxc-rs/nxc-rs/auth/src/lib.rs): Clears username, password, NT hash, LM hash, AES-128 key, AES-256 key, and certificate path on drop.
- [`CertificateAuth`](file:///C:/Users/frimp/Documents/nxc-rs/nxc-rs/auth/src/certificate.rs): Zeroizes decrypted private key bytes when dropped.
- Key derivation routines (`string2key_rc4`, `string2key_aes`, `derive_key_aes`): Intermediate key buffers and UTF-16 byte vectors are zeroized before returning.

### 3.2 Constant-Time Comparisons
To mitigate timing attacks:
- **Kerberos RC4-HMAC**: The 16-byte HMAC-MD5 checksum verification uses constant-time byte comparison.
- **Kerberos AES-CTS**: The 12-byte HMAC-SHA1-96 checksum verification uses constant-time byte comparison.
- **NTLM Signatures**: Verification of SMB message signatures and session signatures uses constant-time comparison.

### 3.3 Cryptographic Algorithms & Rationale
1. **Modern Protocols**:
   - TLS 1.2 and TLS 1.3 for all secure transports (WinRM HTTPS, LDAPS, HTTPS, RDP).
   - AES-128 / AES-256 in CBC or CTS modes for Kerberos and SMB3 channel sealing.
   - SHA-256 for integrity hashing and session binding.
2. **Legacy Protocol Compatibility**:
   - MD4, MD5, and RC4 are implemented strictly for legacy Active Directory protocol interoperability (NTLMv1/v2 authentication, RC4-HMAC Kerberos enctypes).
   - These legacy algorithms are isolated within `nxc-auth` and are never used for internal security functions or database encryption.

---

## 4. Database Security at Rest (`nxc.db`)

### 4.1 Storage Architecture
NetExec-RS stores harvested host metadata, open ports, discovered SMB shares, vulnerabilities, and cracked/dumped credentials in an SQLite database (`~/.nxc/workspaces/default/nxc.db` or current directory `nxc.db`).

### 4.2 Restrictive Access Control
1. **Linux / macOS**:
   - Directory created with mode `0700` (`rwx------`).
   - Database file created with mode `0600` (`rw-------`).
2. **Windows**:
   - Created in `%USERPROFILE%\.nxc\`, inheriting the user's secure default ACL.
   - Permissions validated to ensure no `Everyone` or `Authenticated Users` write/read access.
3. **Encrypted Storage Guidance**:
   - Users are strongly encouraged to store operational workspaces on full-disk encrypted volumes:
     - Windows: BitLocker drive or encrypted VHDX.
     - Linux: LUKS encrypted volume or `fscrypt` directory.
     - macOS: FileVault APFS encrypted volume.
4. **Credential Purging & Lifecycle**:
   - `nxc db --clear-creds`: Immediately purges credential tables and executes `VACUUM` to overwrite SQLite free-list pages.
   - Schema versioning (`PRAGMA user_version`) guarantees atomic migrations and integrity checks.

---

## 5. AI Engine Safety & Guardrails

1. **Secret Masking**:
   - API keys (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) are masked in memory and omitted from all string formatting.
2. **Prompt Injection Mitigations**:
   - Target banners and LDAP attributes are sanitized before injection into LLM prompts.
   - Injection payloads attempting to alter system instructions are intercepted and neutralised.
3. **Execution Guardrails**:
   - Only safe, read-only tools (`query_db`, `search_modules`, `parse_targets`) are allowed by default.
   - Active tools (network port scanning, module execution, credential testing) require `--confirm-ai-exec` or explicit human approval.
   - A simulated `--dry-run` mode is available to inspect AI reasoning and planned tool calls without sending any network traffic.

---

## 6. Vulnerability Disclosure & CVE Process

For vulnerability reports and coordinated disclosure timelines, consult [`SECURITY.md`](file:///C:/Users/frimp/Documents/nxc-rs/SECURITY.md). Cryptographic vulnerabilities receive expedited triage and patch release within 14 days.
