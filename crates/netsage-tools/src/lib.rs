use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;

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
                "name": "ssh_command",
                "description": "Execute a CLI command on a remote host via standard SSH.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Remote host IP or hostname"},
                        "command": {"type": "string", "description": "CLI command to execute"},
                        "username": {"type": "string", "description": "SSH username"},
                        "password": {"type": "string", "description": "SSH password (optional if key is provided)"},
                    },
                    "required": ["host", "command", "username"]
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
        ];
        Self { tools }
    }

    pub async fn call_tool(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        match name {
            "ping_host" => self.ping_host(args).await,
            "dns_lookup" => self.dns_lookup(args).await,
            "port_scan" => self.port_scan(args).await,
            "geoip_lookup" => self.geoip_lookup(args).await,
            "ssh_command" => self.ssh_command(args).await,
            "whois_lookup" => self.whois_lookup(args).await,
            _ => Err(anyhow::anyhow!("Tool not implemented: {}", name)),
        }
    }

    async fn ssh_command(&self, args: Value) -> anyhow::Result<Value> {
        let host = args["host"].as_str().ok_or_else(|| anyhow::anyhow!("Missing host"))?;
        let command = args["command"].as_str().ok_or_else(|| anyhow::anyhow!("Missing command"))?;
        let username = args["username"].as_str().ok_or_else(|| anyhow::anyhow!("Missing username"))?;
        let password = args["password"].as_str();

        let tcp = std::net::TcpStream::connect(format!("{}:22", host))?;
        let mut sess = ssh2::Session::new()?;
        sess.set_tcp_stream(tcp);
        sess.handshake()?;

        if let Some(pw) = password {
            sess.userauth_password(username, pw)?;
        } else {
            sess.userauth_agent(username)?;
        }

        let mut channel = sess.channel_session()?;
        channel.exec(command)?;
        
        use std::io::Read;
        let mut s = String::new();
        channel.read_to_string(&mut s)?;
        
        let mut stderr = String::new();
        channel.stderr().read_to_string(&mut stderr)?;
        
        channel.wait_close()?;

        Ok(json!({
            "status": "success",
            "host": host,
            "stdout": s,
            "stderr": stderr,
            "exit_status": channel.exit_status()?
        }))
    }

    async fn whois_lookup(&self, args: Value) -> anyhow::Result<Value> {
        let domain = args["domain"].as_str().ok_or_else(|| anyhow::anyhow!("Missing domain"))?;
        
        use std::io::{Write, Read};
        let mut stream = std::net::TcpStream::connect("whois.iana.org:43")?;
        stream.write_all(format!("{}\r\n", domain).as_bytes())?;
        
        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        Ok(json!({
            "status": "success",
            "domain": domain,
            "raw": response
        }))
    }

    async fn port_scan(&self, args: Value) -> anyhow::Result<Value> {
        let host = args["host"].as_str().ok_or_else(|| anyhow::anyhow!("Missing host"))?;
        let ports_str = args["ports"].as_str().unwrap_or("1-1024");

        let mut ports = Vec::new();
        if ports_str.contains('-') {
            let parts: Vec<&str> = ports_str.split('-').collect();
            if parts.len() == 2 {
                let start = parts[0].parse::<u16>()?;
                let end = parts[1].parse::<u16>()?;
                for p in start..=end {
                    ports.push(p);
                }
            }
        } else {
            for p in ports_str.split(',') {
                if let Ok(port) = p.trim().parse::<u16>() {
                    ports.push(port);
                }
            }
        }

        let mut open_ports = Vec::new();
        for port in ports {
            let addr = format!("{}:{}", host, port);
            if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(100), tokio::net::TcpStream::connect(&addr)).await {
                open_ports.push(port);
            }
        }

        Ok(json!({
            "status": "success",
            "host": host,
            "open_ports": open_ports,
        }))
    }

    async fn geoip_lookup(&self, args: Value) -> anyhow::Result<Value> {
        let ip_str = args["ip"].as_str().ok_or_else(|| anyhow::anyhow!("Missing ip"))?;
        
        Ok(json!({
            "status": "success",
            "ip": ip_str,
            "city": "San Francisco",
            "country": "United States",
            "isp": "Mock ISP",
            "note": "GeoIP database path not configured, returning mock data"
        }))
    }

    async fn ping_host(&self, args: Value) -> anyhow::Result<Value> {
        let host = args["host"].as_str().ok_or_else(|| anyhow::anyhow!("Missing host"))?;
        let count = args["count"].as_u64().unwrap_or(4) as usize;

        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                use tokio::net::lookup_host;
                let mut addrs = lookup_host(format!("{}:0", host)).await?;
                addrs.next().ok_or_else(|| anyhow::anyhow!("DNS resolution failed"))?.ip()
            }
        };

        let mut results = Vec::new();
        let payload = [0u8; 56];
        for i in 0..count {
            match surge_ping::ping(ip, &payload).await {
                Ok((_, rtt)) => {
                    let rtt_val: f64 = rtt.as_nanos() as f64 / 1_000_000.0;
                    results.push(json!({ "rtt": rtt_val, "seq": i }));
                }
                Err(_) => results.push(json!(null)),
            }
        }

        let successes: Vec<f64> = results.iter()
            .filter_map(|r| r.as_object())
            .filter_map(|o| o.get("rtt"))
            .filter_map(|v| v.as_f64())
            .collect();

        if successes.is_empty() {
            return Ok(json!({
                "status": "error",
                "host": host,
                "error": "No response from host"
            }));
        }

        Ok(json!({
            "status": "success",
            "host": host,
            "sent": count,
            "received": successes.len(),
            "rtt_min": successes.iter().cloned().fold(f64::INFINITY, f64::min),
            "rtt_avg": successes.iter().sum::<f64>() / successes.len() as f64,
            "rtt_max": successes.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        }))
    }

    async fn dns_lookup(&self, args: Value) -> anyhow::Result<Value> {
        let query = args["query"].as_str().ok_or_else(|| anyhow::anyhow!("Missing query"))?;
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        
        match query.parse::<IpAddr>() {
            Ok(ip) => {
                let response = resolver.reverse_lookup(ip).await?;
                let mut names = Vec::new();
                for n in response.into_iter() {
                    names.push(n.to_utf8());
                }
                Ok(json!({
                    "status": "success",
                    "query": query,
                    "type": "PTR",
                    "results": names
                }))
            }
            Err(_) => {
                let response = resolver.lookup_ip(query).await?;
                let mut ips = Vec::new();
                for ip in response.into_iter() {
                    ips.push(ip.to_string());
                }
                Ok(json!({
                    "status": "success",
                    "query": query,
                    "type": "A",
                    "results": ips
                }))
            }
        }
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
