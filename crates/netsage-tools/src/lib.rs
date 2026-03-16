use serde_json::{json, Value};

pub struct ToolRegistry {
    tools: Vec<Value>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        let tools = vec![
            json!({
                "name": "ping_host",
                "description": "Send ICMP echo requests to a host to check connectivity.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "The target hostname or IP address"},
                        "count": {"type": "integer", "description": "Number of packets to send", "default": 4}
                    },
                    "required": ["host"]
                }
            }),
            json!({
                "name": "dns_lookup",
                "description": "Resolve a hostname to IP addresses or vice versa.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "The hostname or IP to resolve"}
                    },
                    "required": ["query"]
                }
            }),
            json!({
                "name": "port_scan",
                "description": "Scan a target host for open TCP ports.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Target hostname or IP"},
                        "ports": {"type": "string", "description": "Port range (e.g., '1-1024' or '80,443')", "default": "1-1024"}
                    },
                    "required": ["host"]
                }
            }),
            json!({
                "name": "arp_scan",
                "description": "Discover local devices on the LAN using ARP requests.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "range_ip": {"type": "string", "description": "Network range in CIDR notation (e.g., '192.168.1.0/24')"}
                    },
                    "required": ["range_ip"]
                }
            }),
            json!({
                "name": "ssh_command",
                "description": "Execute a CLI command on a remote host via standard SSH.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Remote host IP or hostname"},
                        "command": {"type": "string", "description": "CLI command to execute"},
                        "username": {"type": "string", "description": "SSH username"},
                        "password": {"type": "string", "description": "SSH password (optional if key is provided)"},
                        "key_filename": {"type": "string", "description": "Path to SSH private key (optional)"}
                    },
                    "required": ["host", "command", "username"]
                }
            }),
            json!({
                "name": "geoip_lookup",
                "description": "Get geographical and ISP information for a public IP address.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "description": "The public IP address to lookup"}
                    },
                    "required": ["ip"]
                }
            }),
            json!({
                "name": "whois_lookup",
                "description": "Retrieve WHOIS registry information for a domain or IP.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain name or IP address"}
                    },
                    "required": ["domain"]
                }
            }),
            json!({
                "name": "napalm_get_facts",
                "description": "Retrieve standardized device information (vendor, model, serial, uptime) using NAPALM.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Device IP or hostname"},
                        "username": {"type": "string", "description": "Management username"},
                        "password": {"type": "string", "description": "Management password"},
                        "driver": {"type": "string", "description": "NAPALM driver (e.g., 'ios', 'eos', 'junos')", "default": "ios"}
                    },
                    "required": ["host", "username", "password"]
                }
            }),
        ];
        Self { tools }
    }

    pub fn get_schemas(&self) -> Vec<Value> {
        self.tools.clone()
    }

    pub fn get_openai_schemas(&self) -> Vec<Value> {
        self.tools.iter().map(|t| {
            json!({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"]
                }
            })
        }).collect()
    }

    pub fn get_gemini_schemas(&self) -> Vec<Value> {
        self.tools.iter().map(|t| {
            json!({
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"]
            })
        }).collect()
    }
}
