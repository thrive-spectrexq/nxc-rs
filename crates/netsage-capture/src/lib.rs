pub mod topology;
use anyhow::Result;
use pcap::{Capture, Device};
use tracing::info;

pub struct PacketEngine {
    capture: Capture<pcap::Active>,
}

impl PacketEngine {
    pub fn new(interface_name: Option<&str>) -> Result<Self> {
        let device = if let Some(name) = interface_name {
            Device::list()?
                .into_iter()
                .find(|d| d.name == name)
                .ok_or_else(|| anyhow::anyhow!("Interface {} not found", name))?
        } else {
            Device::lookup()?.ok_or_else(|| anyhow::anyhow!("No default interface found"))?
        };

        info!("Starting capture on device: {}", device.name);
        
        let capture = Capture::from_device(device)?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()?;

        Ok(Self { capture })
    }

    pub fn set_filter(&mut self, filter: &str) -> Result<()> {
        self.capture.filter(filter, true)?;
        Ok(())
    }

    pub fn next_packet(&mut self) -> Result<Option<String>> {
        match self.capture.next_packet() {
            Ok(packet) => {
                // Basic representation for now
                Ok(Some(format!("Packet: {} bytes", packet.header.len)))
            }
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
