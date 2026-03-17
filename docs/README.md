# NetSage + NetExec-RS — Project Documentation

NetSage is a next-generation AI-powered network intelligence tool. **NetExec-RS** extends it with a full Rust reimplementation of the NetExec (nxc) network execution framework, adding multi-protocol authentication, credential spraying, post-exploitation modules, and Active Directory enumeration.

## High-Level Architecture

The system is a **pure Rust** Cargo workspace monorepo:

- **NetSage Core** — TUI, Agent Loop, Packet Capture, Session Storage, MCP Server
- **NetExec-RS Layer** — Protocol handlers (SMB, LDAP, WinRM, etc.), Auth engine (NTLM, Kerberos), Module system, Credential database, Target parser, nxc CLI

All nxc-* crates are additive extensions — existing NetSage functionality is unchanged and shared.

## Design Philosophy

- **Agent-First**: Conversational experience — the LLM can invoke nxc tools with approval gating.
- **Single Binary**: Two entry points (`netsage` TUI, `nxc` CLI) from one workspace.
- **Zero Config**: Works out of the box with native tools.
- **Memory-Safe Offensive Tooling**: All protocol implementations (NTLM, Kerberos, SMB) in pure Rust.
- **Audit-Complete**: Every auth attempt, command exec, and credential access logged.

## Approval Modes

1. **READ-ONLY**: Observation and analysis only.
2. **SUPERVISED**: User confirms each tool call (Default).
3. **AUTONOMOUS**: AI executes tools without confirmation (`--allow-autonomous`).

### nxc Risk Classification

| Risk | Colour | Example Tools |
|---|---|---|
| **INFO** | Green | `nxc smb enum_hosts` · `nxc ldap get-users` |
| **PROBE** | Yellow | `nxc smb password spray` · `nxc ldap kerberoast` |
| **ACTIVE** | Orange | `nxc smb exec` · `nxc winrm exec` · `nxc mssql xp_cmdshell` |
| **WRITE** | Red | `nxc smb secretsdump` · `nxc smb sam/lsa` |

## Documentation Index

- [Architecture](architecture.md) — Layered design, component map, dependency graph
- [Agent Runtime](agent_runtime.md) — Agent loop, tool registry, nxc tool integration
- [Security](security.md) — Privilege model, safeguards, responsible use
