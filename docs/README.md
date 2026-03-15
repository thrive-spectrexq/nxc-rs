# NetSage: AI-Powered Network Intelligence

NetSage is a next-generation AI-powered network intelligence tool that lives entirely in the terminal. It enables engineers to diagnose, monitor, scan, and reason about networks using natural language.

## High-Level Architecture

NetSage uses a hybrid **Rust + Python** system:
- **Rust Core**: Handles the Terminal UI (TUI), agent event loop, real-time packet capture, and streaming I/O.
- **Python Tool Engine**: Provides the rich ecosystem of networking libraries (Scapy, Nmap, Paramiko, etc.) and acts as a tool executor.

## Design Philosophy
- **Agent-First**: Conversational experience similar to Claude Code.
- **Single Binary**: Rust binary as the user-facing entry point.
- **Zero Install**: Sidecar Python engine installs transparently.

## Approval Modes
1. **READ-ONLY**: Observation and analysis only.
2. **SUPERVISED**: User confirms each tool call (Default).
3. **AUTONOMOUS**: AI executes tools without confirmation (`--allow-autonomous`).
