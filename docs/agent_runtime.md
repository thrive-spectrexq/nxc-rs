# Agent Runtime

## The Agent Loop

The agent loop manages the conversation flow:
1. User prompt is submitted.
2. Agent calls the configured LLM API (Anthropic, Gemini, or OpenAI) with tool definitions.
3. The LLM streams text and tool use requests.
4. Agent intercepts tool use and requests user approval (if in Supervised mode).
5. If approved, the agent calls the native Rust tools via `ToolRegistry`.
6. Results are fed back to the LLM to continue the reasoning loop.

## Native Tool Registry

NetSage uses a native Rust implementation for all its networking tools, located in the `netsage-tools` crate.

### Why Pure Rust?
- **Speed**: No IPC overhead or process spawning delays.
- **Safety**: Memory safety guarantees and single binary deployment.
- **Simplicity**: No external Python runtime or dependency management required.

### Integrated Tools (NetSage)
- **Ping**: Raw sockets via `surge-ping`
- **DNS**: Async resolution via `trust-dns-resolver`
- **Port Scanning**: High-performance TCP connect scans
- **SSH**: Secure remote execution via `ssh2`
- **GeoIP**: Local IP intelligence
- **Traceroute**: Native traceroute implementation
- **HTTP Probe**: HTTP endpoint probing via `reqwest`

## NetExec-RS Tool Registration

All nxc-protocols and nxc-modules are registered as `NetworkTool` implementations in the existing `ToolRegistry`. The LLM agent can invoke any NetExec-RS capability via natural language — with the same approval gating, audit logging, and TUI visibility as existing NetSage tools.

### nxc Tools (Registered in ToolRegistry)

```rust
// In netsage-tools — nxc tools registered alongside existing tools
registry.register(NxcSmbTool::new(&config.nxc));
registry.register(NxcLdapTool::new(&config.nxc));
registry.register(NxcWinRmTool::new(&config.nxc));
registry.register(NxcMssqlTool::new(&config.nxc));
registry.register(NxcSshTool::new(&config.nxc));
registry.register(NxcPasswordSprayTool::new(&config.nxc));
registry.register(NxcSecretsdumpTool::new(&config.nxc));
registry.register(NxcBloodhoundTool::new(&config.nxc));
registry.register(NxcKerberoastTool::new(&config.nxc));
registry.register(NxcAdcsTool::new(&config.nxc));
```

### Example LLM Interaction

```
User:  I've got creds admin:Password123 for corp.local. What can I access?

Agent: [runs NxcSmbTool: targets=10.0.1.0/24, user=admin, pass=Password123]
       → Found 12 hosts. Admin access on: DC01 (10.0.1.10), FS01 (10.0.1.50)

       [runs NxcSecretsdumpTool: target=DC01, creds=admin:Password123]
       → Dumped 847 NT hashes from NTDS.dit

       [runs NxcKerberoastTool: domain=corp.local, creds=admin:Password123]
       → Captured 3 TGS hashes for kerberoastable accounts
```

### Risk Classification for nxc Tools

| Risk | Colour | Tools |
|---|---|---|
| **INFO** | Green | Host/share enumeration, user listing |
| **PROBE** | Yellow | Password spray, Kerberoast, AS-REP roast |
| **ACTIVE** | Orange | Command execution, file operations |
| **WRITE** | Red | Secretsdump, SAM/LSA dump, DACL write |
