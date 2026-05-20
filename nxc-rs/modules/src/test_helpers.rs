use nxc_protocols::NxcSession;

/// A mock session for testing modules without real network connections.
pub struct MockSession {
    pub protocol_name: &'static str,
    pub target_host: String,
    pub is_admin_flag: bool,
}

impl MockSession {
    pub fn new(protocol: &'static str, target: &str, is_admin: bool) -> Self {
        Self {
            protocol_name: protocol,
            target_host: target.to_string(),
            is_admin_flag: is_admin,
        }
    }
}

impl NxcSession for MockSession {
    fn protocol(&self) -> &'static str {
        self.protocol_name
    }

    fn target(&self) -> &str {
        &self.target_host
    }

    fn is_admin(&self) -> bool {
        self.is_admin_flag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// TODO: Implement MockDb once DatabaseBackend trait is available.
