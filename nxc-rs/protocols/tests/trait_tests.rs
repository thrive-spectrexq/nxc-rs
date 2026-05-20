use nxc_protocols::{NxcProtocol, NxcSession, CommandOutput};
use nxc_auth::{AuthResult, Credentials};
use anyhow::Result;
use async_trait::async_trait;

struct MockSession {
    target: String,
    admin: bool,
}

impl NxcSession for MockSession {
    fn protocol(&self) -> &'static str { "mock" }
    fn target(&self) -> &str { &self.target }
    fn is_admin(&self) -> bool { self.admin }
    
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}

struct MockProtocol;

#[async_trait]
impl NxcProtocol for MockProtocol {
    fn name(&self) -> &'static str { "mock" }
    fn default_port(&self) -> u16 { 9999 }
    
    async fn connect(
        &self,
        target: &str,
        _port: u16,
        _proxy: Option<&str>,
    ) -> Result<Box<dyn NxcSession>> {
        Ok(Box::new(MockSession {
            target: target.to_string(),
            admin: false,
        }))
    }

    async fn authenticate(
        &self,
        _session: &mut dyn NxcSession,
        _creds: &Credentials,
    ) -> Result<AuthResult> {
        Ok(AuthResult::failure("Authentication failed", None))
    }

    async fn execute(
        &self,
        _session: &dyn NxcSession,
        _cmd: &str,
    ) -> Result<CommandOutput> {
        Ok(CommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
        })
    }
}

#[tokio::test]
async fn test_protocol_trait_base_functionality() {
    let proto = MockProtocol;
    assert_eq!(proto.name(), "mock");
    assert_eq!(proto.default_port(), 9999);
    
    let session = proto.connect("10.0.0.1", 9999, None).await.unwrap();
    
    assert_eq!(session.protocol(), "mock");
    assert_eq!(session.target(), "10.0.0.1");
    assert_eq!(session.is_admin(), false);
}
