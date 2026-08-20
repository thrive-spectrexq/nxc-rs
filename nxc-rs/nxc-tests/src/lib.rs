//! # NXC Integration Tests
//!
//! This crate contains cross-crate integration tests for the NetExec-RS workspace.
//! It verifies that components like auth, protocols, modules, and database
//! interact correctly together.

#[cfg(test)]
mod integration_tests {
    use nxc_auth::Credentials;
    use nxc_modules::ModuleOption;
    use nxc_protocols::smb::SmbProtocol;
    use nxc_protocols::winrm::WinrmProtocol;
    use nxc_protocols::NxcProtocol;
    use std::time::Duration;

    #[test]
    fn test_credentials_builder_and_display() {
        // Test that the Credentials builder works and handles secrets correctly.
        let creds = Credentials::password("Administrator", "SuperSecret123!", Some("CORP"));

        assert_eq!(creds.username, "Administrator");
        assert_eq!(creds.domain.as_deref(), Some("CORP"));
        assert_eq!(creds.password.as_deref(), Some("SuperSecret123!"));

        // Ensure Display trait correctly masks passwords in output.
        let display_str = creds.to_string();
        assert!(display_str.contains("CORP\\Administrator"));
        assert!(display_str.contains("password"));
        assert!(!display_str.contains("SuperSecret123!"));
    }

    #[test]
    fn test_protocol_instantiation() {
        // Test that protocols can be instantiated and configured.
        let smb = SmbProtocol::with_timeout(Duration::from_secs(5));
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
        let options = [ModuleOption {
            name: "COMMAND".to_string(),
            description: "Command to execute".to_string(),
            required: true,
            default: None,
        }];

        assert_eq!(options.len(), 1);
        assert_eq!(options[0].name, "COMMAND");
    }

    pub struct MockSession {
        pub protocol: &'static str,
        pub target: String,
        pub is_admin: bool,
    }

    impl nxc_protocols::NxcSession for MockSession {
        fn protocol(&self) -> &'static str {
            self.protocol
        }
        fn target(&self) -> &str {
            &self.target
        }
        fn is_admin(&self) -> bool {
            self.is_admin
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    }


}
