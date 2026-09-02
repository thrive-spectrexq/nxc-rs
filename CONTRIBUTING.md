# Contributing to NetExec-RS

Thank you for your interest in contributing to NetExec-RS! We welcome all contributions, from code to documentation to bug reports.

## Getting Started

### Prerequisites

To build and test NetExec-RS, you will need:
- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- `cargo` (comes with Rust)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/thrive-spectrexq/nxc-rs.git
   cd nxc-rs
   ```

2. Build the project:
   ```bash
   cargo build
   ```

## Development Workflow

### Project Structure

NetExec-RS is organized as a unified Rust workspace:
- `nxc-rs/nxc`: The primary CLI binary application.
- `nxc-rs/auth`: Authentication engines (NTLM SSP, Kerberos v5, PKINIT, certificate parsing, DPAPI/registry).
- `nxc-rs/protocols`: Enterprise protocol implementations (SMB, LDAP, WinRM, SSH, RDP, MSSQL, FTP, VNC, WMI).
- `nxc-rs/modules`: Extensible post-enumeration and offensive modules.
- `nxc-rs/db`: SQLite persistence and workspace schema management.
- `nxc-rs/targets`: Target specification parser and asynchronous `ExecutionEngine`.
- `nxc-rs/ai`: LLM integration, planner, tool registry, and prompt safety guardrails.
- `nxc-rs/resilience`: Circuit breakers, rate-limiting, jitter, and retry policies.
- `nxc-rs/nxc-sessions`: State management and session serialization.
- `nxc-rs/reporting`: Multi-format exporters (JSON, CSV, HTML, Markdown).
- `nxc-rs/nxc-tests`: Integration test suites and mock infrastructure.

### Running Tests & Verification

Run tests across the entire workspace:
```bash
cargo test --workspace
```

Run tests for a single crate:
```bash
cargo test -p nxc-auth
cargo test -p nxc-protocols
```

Run lints and formatting checks:
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets
```

Run dependency vulnerability and license checks:
```bash
cargo deny check
cargo audit
```

## Pull Request Checklist

Before submitting a Pull Request, verify every item on this checklist:

- [ ] **Formatting**: Code is formatted via `cargo fmt --all`.
- [ ] **Lints**: Passes `cargo clippy --workspace --all-targets` with zero warnings.
- [ ] **Tests**: All unit and integration tests pass via `cargo test --workspace`.
- [ ] **Zero Panics**: No unwrap() or expect() calls in production crate code (tests excluded). Use domain `Result` and `?` error propagation.
- [ ] **Memory Safety**: No `unsafe` code. The workspace enforces `unsafe_code = "deny"`.
- [ ] **Secrets Protection**: Any new sensitive data structures implement `zeroize::Zeroize` and `#[zeroize(drop)]`.
- [ ] **Logging Hygiene**: Never use `println!` or `eprintln!` inside library crates (`nxc-rs/*` except `nxc`). Always use `tracing` events (`info!`, `debug!`, `warn!`, `error!`).
- [ ] **Constant-Time Crypto**: Any cryptographic comparison must use constant-time operations (`subtle` or `constant_time_eq`).
- [ ] **Documentation**: Public structs, enums, and functions include clear doc comments (`///`).

### Commit Message Format
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat: add SMB3 tree connect property tests`
- `fix: prevent timing leak in Kerberos HMAC verification`
- `docs: update threat model and Windows ACL guidance`
- `refactor: extract module helper utilities to core crate`
- `test: add mock LDAP server integration test`

## Submitting a Pull Request

1. Fork the repository and create a descriptive branch:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Make changes following the checklist above.
3. Commit with Conventional Commit messages.
4. Push your branch to your fork and submit a PR against `master`.

## Community

- Report bugs or request features via [GitHub Issues](https://github.com/thrive-spectrexq/nxc-rs/issues).
- Discuss ideas in the [GitHub Discussions](https://github.com/thrive-spectrexq/nxc-rs/discussions).

Happy hacking!
