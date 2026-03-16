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

### Integrated Tools
- **Ping**: Ported using raw sockets (via `surge-ping`).
- **DNS**: Native asynchronous resolution (via `trust-dns-resolver`).
- **Port Scanning**: High-performance TCP connect scans.
- **SSH**: Secure remote execution (via `ssh2`).
- **GeoIP**: Local IP intelligence.
