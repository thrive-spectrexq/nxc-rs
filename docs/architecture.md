# Architecture Overview

## Layered Design

| Layer | Technology | Responsibility |
| :--- | :--- | :--- |
| **L5 — AI Reasoning** | Claude API / Gemini / GPT | Language understanding, tool selection, interpretation. |
| **L4 — Agent Loop** | Rust (Tokio) | SSE streaming, approval gating, session memory. |
| **L3 — TUI / UX** | Rust (Ratatui) | Real-time rendering, dashboards, packet viewer. |
| **L2 — Native Tools** | Rust (netsage-tools) | Native implementation of networking tools. |
| **L1 — System** | OS / Sockets | Raw packet capture, kernel sockets, privilege management. |

## Component Map

- **netsage-tui**: Ratatui-based renderer for dashboards and chat.
- **netsage-agent**: Tokio async agent loop and LLM client.
- **netsage-tools**: Native Rust implementation of networking tools (Ping, DNS, SSH, etc.).
- **netsage-capture**: libpcap bindings and BPF filter compiler.
- **netsage-session**: SQLite persistent session storage.
- **netsage-mcp**: MCP server implementation for native tools.
