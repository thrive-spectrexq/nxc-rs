use nxc_protocols::{NxcProtocol, NxcSession, ProtocolConfig};
use anyhow::Result;
use async_trait::async_trait;

// Mock session and protocol to test the trait bounds and behavior
struct MockSession {
    target: String,
    admin: bool,
}

impl NxcSession for MockSession {
    fn protocol(&self) -> &'static str { "mock" }
    fn target(&self) -> &str { &self.target }
    fn is_admin(&self) -> bool { self.admin }
    
    fn downcast_any(&self) -> &dyn std::any::Any { self }
    fn downcast_any_mut(&mut self) -> &mut dyn std::any::Any { self }
}

struct MockProtocol;

#[async_trait]
impl NxcProtocol for MockProtocol {
    fn name(&self) -> &'static str { "mock" }
    fn port(&self) -> u16 { 9999 }
    
    async fn connect(&self, target: &str, _config: &ProtocolConfig) -> Result<Box<dyn NxcSession>> {
        Ok(Box::new(MockSession {
            target: target.to_string(),
            admin: false,
        }))
    }
}

#[tokio::test]
async fn test_protocol_trait_base_functionality() {
    let proto = MockProtocol;
    assert_eq!(proto.name(), "mock");
    assert_eq!(proto.port(), 9999);
    
    let config = ProtocolConfig::default();
    let session = proto.connect("10.0.0.1", &config).await.unwrap();
    
    assert_eq!(session.protocol(), "mock");
    assert_eq!(session.target(), "10.0.0.1");
    assert_eq!(session.is_admin(), false);
}
