# Core Architecture

NetExec-RS is not just a port of the Python NetExec tool; it is a ground-up reimagination built on asynchronous Rust (Tokio) designed for 10x performance and modularity. This document is a deep-dive into the internal subsystems.

## High-Level Component Topology

The repository is built as a Cargo Workspace containing multiple distinct crates:

1. **`nxc`:** The frontline CLI binaries. Connects the user to the engine.
2. **`nxc-ai`:** The LLM integration crate (Elite Reaper/Gemini). Translates natural language into programmatic actions.
3. **`nxc-targets`:** Intelligent target parsing (CIDR, IP ranges, Hostname files, Nmap XML ingestion).
4. **`nxc-auth`:** Cryptographic authentication handlers (NTLM SSP, Kerberos, Hashes, Certificates).
5. **`nxc-protocols`:** The network execution engines (SMB, LDAP, MSSQL, SSH, WinRM, DNS, etc.).
6. **`nxc-modules`:** The dynamic post-exploitation payload suite (135+ modules).
7. **`nxc-db`:** Centralized state SQLite database (workspace credentials, hosts, loot).

## The Trait System

The core design centers around three primary Rust traits that define abstraction contracts:

### 1. `NxcProtocol`
Every network protocol implements `NxcProtocol`. This defines how the framework connects, authenticates, and executes instructions on a remote target.
```rust
#[async_trait]
pub trait NxcProtocol: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_port(&self) -> u16;
    
    // Core Handshake
    async fn connect(&self, target: &Target) -> Result<Box<dyn NxcSession>>;
}
```

### 2. `NxcSession`
Once a protocol connects, it returns an `NxcSession`. This is an authenticated (or anonymous) socket wrapper specific to the protocol (e.g. `SmbSession`, `LdapSession`). Modules leverage sessions to dispatch low-level RPC/network calls.

### 3. `NxcModule`
Modules are self-contained offensive tasks (e.g., dropping a backdoor, querying the registry) that implement `NxcModule`. They declare which protocols they are compatible with.

```rust
#[async_trait]
pub trait NxcModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn supported_protocols(&self) -> Vec<Protocol>;
    
    // The core execution logic
    async fn run(&self, session: &dyn NxcSession, args: &ModuleArgs) -> Result<ModuleResult>;
}
```

## Concurrency Model

NetExec-RS achieves its legendary speed through absolute asynchronous IO. 
When targeting a `/16` subnet with 65,000 IPs:
- The `nxc` CLI hands the stream of IPs to the `ExecutionEngine`.
- The engine spins up `tokio::task::spawn` green threads for every target limited by a concurrent connection pool (default: 100).
- Lockless channels (`tokio::sync::mpsc`) aggregate results back to the stdout logger flawlessly without threading deadlocks.
