//! # NXC Integration Tests
//!
//! This crate contains cross-crate integration tests for the NetExec-RS workspace.
//! It verifies that components like auth, protocols, modules, and database
//! interact correctly together.

#[cfg(test)]
mod integration_tests {
    use nxc_auth::Credentials;
    use nxc_protocols::smb::SmbProtocol;
    use nxc_protocols::winrm::WinrmProtocol;
    use nxc_protocols::NxcProtocol;
    use nxc_modules::{NxcModule, ModuleOption};
    use std::time::Duration;

    #[test]
    fn test_credentials_builder_and_display() {
        // Test that the Credentials builder works and handles secrets correctly.
        let creds = Credentials::new("Administrator".to_string())
            .with_password("SuperSecret123!".to_string())
            .with_domain("CORP".to_string());

        assert_eq!(creds.username, "Administrator");
        assert_eq!(creds.domain.as_deref(), Some("CORP"));
        assert_eq!(creds.password.as_deref(), Some("SuperSecret123!"));
        
        // Ensure Display trait correctly masks passwords in output.
        let display_str = creds.to_string();
        assert!(display_str.contains("CORP\\Administrator"));
        assert!(display_str.contains("Password: ***"));
        assert!(!display_str.contains("SuperSecret123!"));
    }

    #[test]
    fn test_protocol_instantiation() {
        // Test that protocols can be instantiated and configured.
        let smb = SmbProtocol::new().with_timeout(Duration::from_secs(5));
        assert_eq!(smb.name(), "smb");
        assert_eq!(smb.default_port(), 445);
        assert!(smb.supports_exec());

        let winrm = WinrmProtocol::new().with_timeout(Duration::from_secs(5));
        assert_eq!(winrm.name(), "winrm");
        assert_eq!(winrm.default_port(), 5985);
        assert!(winrm.supports_exec());
    }

    #[test]
    fn test_module_options_parsing() {
        // A placeholder for parsing module options across components.
        let options = vec![
            ModuleOption {
                key: "COMMAND".to_string(),
                value: "whoami".to_string(),
                description: "Command to execute".to_string(),
                required: true,
            }
        ];
        
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].key, "COMMAND");
    }
}
