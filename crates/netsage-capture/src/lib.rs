use anyhow::Result;
use chrono::Utc;
use netsage_common::{AppEvent, PacketSummary};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tracing::{error, info};

pub mod ingestion;
pub mod topology;

use crate::topology::SharedTopology;
use crate::topology::TopologyGraph;

#[cfg(feature = "pcap")]
use pcap::{Capture, Device};

pub struct CaptureEngine {
    event_tx: broadcast::Sender<AppEvent>,
    topology: SharedTopology,
    #[cfg(feature = "pcap")]
    capture: Arc<Mutex<Capture<pcap::Active>>>,
}

impl CaptureEngine {
    pub fn new(
        event_tx: broadcast::Sender<AppEvent>,
        interface_name: Option<&str>,
    ) -> Result<Self> {
        let topology = Arc::new(Mutex::new(TopologyGraph::new()));

        #[cfg(feature = "pcap")]
        {
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

            Ok(Self {
                event_tx,
                topology,
                capture: Arc::new(Mutex::new(capture)),
            })
        }
        #[cfg(not(feature = "pcap"))]
        {
            // Even without pcap, we can have an engine that might receive remote events
            Ok(Self { event_tx, topology })
        }
    }

    pub fn get_topology(&self) -> SharedTopology {
        self.topology.clone()
    }

    pub fn start(&self) {
        let tx = self.event_tx.clone();
        let topology = self.topology.clone();

        #[cfg(feature = "pcap")]
        {
            let capture = self.capture.clone();
            tokio::task::spawn_blocking(move || {
                loop {
                    let mut cap = capture.lock().unwrap();
                    match cap.next_packet() {
                        Ok(packet) => {
                            // Basic dissection logic
                            let mut proto = "Unknown".to_string();
                            let mut src_ip = None;
                            let mut dst_ip = None;

                            // Very basic dissection for demo purposes
                            // In a real app, use etherparse properly here
                            // For v1.0, we want at least IP visibility
                            if packet.data.len() > 34 {
                                // IPv4 check (Ethernet type 0x0800)
                                if packet.data[12] == 0x08 && packet.data[13] == 0x00 {
                                    src_ip = Some(format!(
                                        "{}.{}.{}.{}",
                                        packet.data[26],
                                        packet.data[27],
                                        packet.data[28],
                                        packet.data[29]
                                    ));
                                    dst_ip = Some(format!(
                                        "{}.{}.{}.{}",
                                        packet.data[30],
                                        packet.data[31],
                                        packet.data[32],
                                        packet.data[33]
                                    ));
                                    proto = match packet.data[23] {
                                        6 => "TCP".to_string(),
                                        17 => "UDP".to_string(),
                                        1 => "ICMP".to_string(),
                                        _ => "IP".to_string(),
                                    };
                                }
                            }

                            if let (Some(ref src), Some(ref dst)) = (&src_ip, &dst_ip) {
                                if let Ok(mut graph) = topology.lock() {
                                    graph.add_node(src.clone(), src.clone(), "host".to_string());
                                    graph.add_node(dst.clone(), dst.clone(), "host".to_string());
                                    graph.add_edge(src.clone(), dst.clone());
                                }
                            }

                            let summary = PacketSummary {
                                timestamp: Utc::now(),
                                length: packet.header.len,
                                protocol: proto,
                                src_ip,
                                dst_ip,
                                src_port: None,
                                dst_port: None,
                            };
                            let _ = tx.send(AppEvent::PacketCaptured(summary));
                        }
                        Err(pcap::Error::TimeoutExpired) => continue,
                        Err(e) => {
                            error!("Capture engine error: {}", e);
                            break;
                        }
                    }
                }
            });
        }
    }
}
