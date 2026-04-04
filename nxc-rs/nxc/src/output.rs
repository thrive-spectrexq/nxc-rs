//! # NXC Output Logger
//!
//! Colored terminal output matching NetExec's NXCAdapter format:
//! `PROTO  host            port   hostname         [+/-/*] message`

use colored::Colorize;
use std::fmt;

/// NXC-style output context for a protocol connection.
#[derive(Debug, Clone)]
pub struct NxcOutput {
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub hostname: String,
}

#[allow(dead_code)]
impl NxcOutput {
    pub fn new(protocol: &str, host: &str, port: u16, hostname: Option<&str>) -> Self {
        Self {
            protocol: protocol.to_uppercase(),
            host: host.to_string(),
            port,
            hostname: hostname.unwrap_or("").to_string(),
        }
    }

    /// Format the prefix: `PROTO  host            port   hostname`
    fn prefix(&self) -> String {
        let proto_color = match self.protocol.to_lowercase().as_str() {
            "smb" => self.protocol.bold().green(),
            "ldap" => self.protocol.bold().blue(),
            "winrm" => self.protocol.bold().cyan(),
            "ssh" => self.protocol.bold().yellow(),
            "mssql" => self.protocol.bold().magenta(),
            "http" | "https" => self.protocol.bold().bright_cyan(),
            "rdp" | "vnc" => self.protocol.bold().bright_blue(),
            "ftp" | "nfs" => self.protocol.bold().bright_yellow(),
            _ => self.protocol.bold().white(),
        };

        format!(
            "{:<8} {:<15} {:<6} {:<16}",
            proto_color,
            self.host.cyan(),
            self.port.to_string().yellow(),
            if self.hostname.is_empty() {
                "NONE".dimmed().to_string()
            } else {
                self.hostname.bold().white().to_string()
            }
        )
    }

    /// `[◈]` informational display — blue.
    pub fn display(&self, msg: &str) {
        println!("{} {} {}", self.prefix(), "◈".bold().blue(), msg);
    }

    /// `[✔]` success — green. Use for auth successes.
    pub fn success(&self, msg: &str) {
        println!("{} {} {}", self.prefix(), "✔".bold().green(), msg);
    }

    /// `[★]` admin success (Pwn3d!) — yellow highlight.
    pub fn pwned(&self, msg: &str) {
        println!(
            "{} {} {} {}",
            self.prefix(),
            "★".bold().yellow(),
            msg.bold().green(),
            "💀 (Pwn3d!)".bold().yellow()
        );
    }

    /// `[✘]` failure — red. Use for auth failures.
    pub fn fail(&self, msg: &str) {
        println!("{} {} {}", self.prefix(), "✘".bold().red(), msg.dimmed());
    }

    /// Highlighted important message — yellow.
    pub fn highlight(&self, msg: &str) {
        println!("{} {}", self.prefix(), msg.bold().yellow());
    }

    /// `[!]` error — red bold.
    pub fn error(&self, msg: &str) {
        eprintln!("{} {} {}", self.prefix(), "⚠".bold().red(), msg.red());
    }
}

impl fmt::Display for NxcOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix())
    }
}

/// Global-level output (not tied to a specific connection).
pub struct NxcGlobalOutput;

#[allow(dead_code)]
impl NxcGlobalOutput {
    pub fn banner(version: &str, codename: &str) {
        let spider = format!(
            r#"
           {}   {}
          {}   {}
          {}   {}
          {}( ){}
          {}={ }={}
         {} {} {}
         {} {} {}
           {}   {}
"#,
            ".".cyan().bold(), ".".cyan().bold(),
            ".|".cyan().bold(), "|.".cyan().bold(),
            "||".cyan().bold(), "||".cyan().bold(),
            "\\\\".cyan().bold(), "//".cyan().bold(),
            ".[".cyan().bold(), " ".white().bold(), "].".cyan().bold(),
            "/ /".cyan().bold(), "˙-˙".yellow().bold(), "\\ \\".cyan().bold(),
            "˙".cyan().bold(), "\\ /".yellow().bold(), "˙".cyan().bold(),
            "˙".cyan().bold(), "˙".cyan().bold()
        );

        let text = format!(
            r#"
      _      _____  _____  _____ __  __  _____  ____      ____  ____
     | \ | || ____||_   _|| ____|\ \/ / | ____|/ ___|    |  _ \/ ___|
     |  \| ||  _|    | |  |  _|   \  /  |  _| | |        | |_) \___ \
     | |\  || |___   | |  | |___  /  \  | |___| |___  __ |  _ < ___) |
     |_| \_||_____|  |_|  |_____|/_/\_\ |_____|\____||__||_| \_\____/

    NetExec-RS — {}

    Version : {}
    Codename: {}
    Maintained by: {}
"#,
            "The Network Execution Tool (Pure Rust)".white().bold(),
            version.yellow().bold(),
            codename.yellow().bold(),
            "@thrive-spectrexq".yellow().bold()
        );

        println!("{}{}", spider, text);
    }

    pub fn info(msg: &str) {
        println!("{} {}", "🕷".bold().blue(), msg);
    }

    pub fn success(msg: &str) {
        println!("{} {}", "✔".bold().green(), msg);
    }

    pub fn warn(msg: &str) {
        println!("{} {}", "⚠".bold().yellow(), msg.yellow());
    }

    pub fn error(msg: &str) {
        eprintln!("{} {}", "✘".bold().red(), msg.red());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nxc_output_creation() {
        let output = NxcOutput::new("smb", "192.168.1.10", 445, Some("DC01"));
        assert_eq!(output.protocol, "SMB");
        assert_eq!(output.host, "192.168.1.10");
        assert_eq!(output.port, 445);
        assert_eq!(output.hostname, "DC01");
    }

    #[test]
    fn test_nxc_output_no_hostname() {
        let output = NxcOutput::new("ssh", "10.0.0.1", 22, None);
        assert_eq!(output.hostname, "");
    }
}
