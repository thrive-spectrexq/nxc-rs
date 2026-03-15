# Agent Runtime & Python Engine

## The Agent Loop

The agent loop manages the conversation flow:
1. User prompt is submitted.
2. Agent calls Claude `/v1/messages` with tool definitions.
3. Claude streams text and `tool_use` blocks.
4. Agent intercepts `tool_use` and requests user approval.
5. If approved, the **Python Bridge** executes the tool.
6. Result is streamed back to Claude to continue the turn.

## Python Tool Engine (Sidecar)

The Python engine is a standalone process spawned by the Rust binary. 

### Why Python?
Unmatched ecosystem for networking:
- **Scapy**: Packet crafting/capture.
- **Nmap**: Port scanning and service discovery.
- **NAPALM / Netmiko**: Multi-vendor automation.
- **Paramiko**: SSH communication.

### Communication Protocol
JSON-RPC 2.0 over a Unix domain socket (or named pipe on Windows).

```json
{
  "jsonrpc": "2.0",
  "id": "call-001",
  "method": "execute_tool",
  "params": {
    "tool": "ping_host",
    "args": { "host": "8.8.8.8", "count": 4 }
  }
}
```
