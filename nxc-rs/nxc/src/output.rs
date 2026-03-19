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
        format!(
            "{:<8} {:<15} {:<6} {:<16}",
            self.protocol.bold().blue(),
            self.host,
            self.port,
            if self.hostname.is_empty() {
                "NONE".to_string()
            } else {
                self.hostname.clone()
            }
        )
    }

    /// `[*]` informational display — blue.
    pub fn display(&self, msg: &str) {
        println!("{} {} {}", self.prefix(), "[*]".bold().blue(), msg);
    }

    /// `[+]` success — green. Use for auth successes.
    pub fn success(&self, msg: &str) {
        println!("{} {} {}", self.prefix(), "[+]".bold().green(), msg);
    }

    /// `[+]` admin success (Pwn3d!) — yellow highlight.
    pub fn pwned(&self, msg: &str) {
        println!(
            "{} {} {} {}",
            self.prefix(),
            "[+]".bold().green(),
            msg,
            "(Pwn3d!)".bold().yellow()
        );
    }

    /// `[-]` failure — red. Use for auth failures.
    pub fn fail(&self, msg: &str) {
        println!("{} {} {}", self.prefix(), "[-]".bold().red(), msg);
    }

    /// Highlighted important message — yellow.
    pub fn highlight(&self, msg: &str) {
        println!("{} {}", self.prefix(), msg.bold().yellow());
    }

    /// `[!]` error — red bold.
    pub fn error(&self, msg: &str) {
        eprintln!("{} {} {}", self.prefix(), "[!]".bold().red(), msg.red());
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
    pub fn banner() {
        let banner = r#"
     .   .
    .|   |.     _   _          _     _____
    ||   ||    | \ | |   ___  | |_  | ____| __  __   ___    ___
    \\( )//    |  \| |  / _ \ | __| |  _|   \ \/ /  / _ \  / __|
    .=[ ]=.    | |\  | |  __/ | |_  | |___   >  <  |  __/ | (__
   / /`-`\ \   |_| \_|  \___|  \__| |_____| /_/\_\  \___|  \___|
   ` \   / `
     `   `
"#;
        println!("{}", banner.bold().cyan());
    }

    pub fn info(msg: &str) {
        println!("{} {}", "[*]".bold().blue(), msg);
    }

    pub fn success(msg: &str) {
        println!("{} {}", "[+]".bold().green(), msg);
    }

    pub fn warn(msg: &str) {
        println!("{} {}", "[!]".bold().yellow(), msg.yellow());
    }

    pub fn error(msg: &str) {
        eprintln!("{} {}", "[!]".bold().red(), msg.red());
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
