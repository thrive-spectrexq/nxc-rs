use super::NxcTool;
use anyhow::{Context, Result};
use async_trait::async_trait;
use nxc_auth::Credentials;
use nxc_protocols::Protocol;
use nxc_targets::{ExecutionEngine, ExecutionOpts, Target};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct ProtocolTool;

#[async_trait]
impl NxcTool for ProtocolTool {
    fn name(&self) -> &'static str {
        "run_protocol"
    }

    fn description(&self) -> &'static str {
        "Run an nxc protocol (e.g., smb, ssh, winrm) against a set of targets with optional credentials."
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "protocol": {
                    "type": "string",
                    "enum": ["smb", "ssh", "winrm", "wmi", "ftp", "vnc", "nfs", "adb", "network", "opcua", "ldap", "mssql", "rdp", "http", "redis", "postgres", "mysql", "snmp", "docker", "dns", "ipmi", "ilo", "kube", "mqtt", "modbus", "exchange", "telnet"],
                    "description": "The protocol to run"
                },
                "targets": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "List of target IPs or hostnames"
                },
                "username": { "type": "string", "description": "Optional username" },
                "password": { "type": "string", "description": "Optional password" },
                "hash": { "type": "string", "description": "Optional NTLM hash" },
                "module": { "type": "string", "description": "Optional module to run" }
            },
            "required": ["protocol", "targets"]
        })
    }

    async fn call(&self, args: Value) -> Result<Value> {
        let protocol_name = args["protocol"].as_str().context("Missing protocol")?;
        let targets_list = args["targets"].as_array().context("Missing targets list")?;

        let protocol_enum = protocol_name.parse::<Protocol>().context("Unsupported protocol")?;

        let mut targets = Vec::new();
        for t in targets_list {
            if let Some(t_str) = t.as_str() {
                targets.push(Target::new(t_str.parse().context("Invalid target IP")?));
            }
        }

        let mut creds = Vec::new();
        let username = args["username"].as_str().unwrap_or("");
        let password = args["password"].as_str();
        let hash = args["hash"].as_str();

        if !username.is_empty() {
            if let Some(p) = password {
                creds.push(Credentials::password(username, p, None));
            } else if let Some(h) = hash {
                creds.push(Credentials::nt_hash(username, h, None));
            } else {
                creds.push(Credentials::password(username, "", None));
            }
        } else {
            creds.push(Credentials::null_session());
        }

        let mut opts = ExecutionOpts::default();
        if let Some(module) = args["module"].as_str() {
            opts.modules.push(module.to_string());
        }

        let engine = ExecutionEngine::new(opts);

        // This is a bit tricky: we need to instantiate the protocol handler
        // Since we are in the ai crate, we might need a factory or registry from protocols/nxc.
        // For now, I'll assume we can get it from somewhere or create it.
        // Actually, let's create a factory in nxc-protocols or here.

        // Refactoring thought: NxcProtocol implementation usually lives in individual crates,
        // but it's re-exported in nxc-rs.

        // I'll implement a simple factory here for now, or use NxcProtocol::all() if available.

        let protocol_handler: Arc<dyn nxc_protocols::NxcProtocol> = match protocol_enum {
            Protocol::Smb => Arc::new(nxc_protocols::smb::SmbProtocol::new()),
            Protocol::Ssh => Arc::new(nxc_protocols::ssh::SshProtocol::new()),
            Protocol::Http => Arc::new(nxc_protocols::http::HttpProtocol::default()),
            Protocol::Ldap => Arc::new(nxc_protocols::ldap::LdapProtocol::new()),
            Protocol::WinRm => Arc::new(nxc_protocols::winrm::WinrmProtocol::new()),
            Protocol::Mssql => Arc::new(nxc_protocols::mssql::MssqlProtocol::new()),
            Protocol::Rdp => Arc::new(nxc_protocols::rdp::RdpProtocol::new()),
            Protocol::Redis => Arc::new(nxc_protocols::redis::RedisProtocol::new()),
            Protocol::Postgres => Arc::new(nxc_protocols::postgresql::PostgresProtocol::new()),
            Protocol::Mysql => Arc::new(nxc_protocols::mysql::MysqlProtocol::new()),
            Protocol::Snmp => Arc::new(nxc_protocols::snmp::SnmpProtocol::new()),
            Protocol::Docker => Arc::new(nxc_protocols::docker::DockerProtocol::new()),
            Protocol::Dns => Arc::new(nxc_protocols::dns::DnsProtocol::new()),
            Protocol::Ipmi => Arc::new(nxc_protocols::ipmi::IpmiProtocol::new()),
            Protocol::Ilo => Arc::new(nxc_protocols::ilo::IloProtocol::new()),
            Protocol::Kube => Arc::new(nxc_protocols::kube::KubeProtocol::new()),
            Protocol::Wmi => Arc::new(nxc_protocols::wmi::WmiProtocol::new()),
            Protocol::Ftp => Arc::new(nxc_protocols::ftp::FtpProtocol::new()),
            Protocol::Vnc => Arc::new(nxc_protocols::vnc::VncProtocol::new()),
            Protocol::Nfs => Arc::new(nxc_protocols::nfs::NfsProtocol::new()),
            Protocol::Adb => Arc::new(nxc_protocols::adb::AdbProtocol::new()),
            Protocol::Network => Arc::new(nxc_protocols::network::NetworkProtocol::new(
                false, None, false, false, false, false, false,
            )),
            #[cfg(feature = "opcua-support")]
            Protocol::OpcUa => Arc::new(nxc_protocols::opcua::OpcUaProtocol::new()),
            #[cfg(not(feature = "opcua-support"))]
            Protocol::OpcUa => anyhow::bail!(
                "OPC-UA support is not enabled. Recompile with the 'opcua-support' feature."
            ),
            Protocol::Mqtt => Arc::new(nxc_protocols::mqtt::MqttProtocol::new()),
            Protocol::Modbus => Arc::new(nxc_protocols::modbus::ModbusProtocol::new()),
            Protocol::Exchange => Arc::new(nxc_protocols::exchange::ExchangeProtocol::new()),
            Protocol::Telnet => Arc::new(nxc_protocols::telnet::TelnetProtocol::new()),
        };

        let results = engine.run(protocol_handler, targets, creds).await;

        Ok(json!({ "results": results }))
    }
}
