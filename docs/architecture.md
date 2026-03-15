# Architecture Overview

## Layered Design

| Layer | Technology | Responsibility |
| :--- | :--- | :--- |
| **L5 — AI Reasoning** | Claude API | Language understanding, tool selection, interpretation. |
| **L4 — Agent Loop** | Rust (Tokio) | SSE streaming, approval gating, session memory. |
| **L3 — TUI / UX** | Rust (Ratatui) | Real-time rendering, dashboards, packet viewer. |
| **L2 — Tool Engine** | Python (IPC) | Execution of Scapy, Nmap, Paramiko, etc. |
| **L1 — System** | OS / Sockets | Raw packet capture, kernel sockets, privilege management. |

## Component Map

- **netsage-tui**: Ratatui-based renderer for dashboards and chat.
- **netsage-agent**: Tokio async agent loop and Claude client.
- **netsage-tools**: JSON Schema registry for tool definitions.
- **netsage-pybridge**: IPC layer (Unix socket / named pipe) for Python engine.
- **netsage-capture**: libpcap bindings and BPF filter compiler.
- **netsage-session**: SQLite persistent session storage.
- **python/netsage_tools**: The Python sidecar containing the tool logic.
