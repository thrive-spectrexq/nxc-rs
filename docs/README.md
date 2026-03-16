# NetSage: AI-Powered Network Intelligence

NetSage is a next-generation AI-powered network intelligence tool that lives entirely in the terminal. It enables engineers to diagnose, monitor, scan, and reason about networks using natural language.

## High-Level Architecture

NetSage is a pure Rust system:
- **Rust Core**: Handles the Terminal UI (TUI), agent event loop, real-time packet capture, and native networking tools.
- **Native Tools**: All investigations (Ping, DNS, SSH, etc.) are implemented natively within the `netsage-tools` crate.

## Design Philosophy
- **Agent-First**: Conversational experience similar to Claude Code.
- **Single Binary**: Portability and performance with no external runtime dependencies.
- **Zero Config**: Works out of the box with native tools.

## Approval Modes
1. **READ-ONLY**: Observation and analysis only.
2. **SUPERVISED**: User confirms each tool call (Default).
3. **AUTONOMOUS**: AI executes tools without confirmation (`--allow-autonomous`).
