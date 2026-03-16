pub mod topology;
pub mod ingestion;
use anyhow::Result;
use tracing::{info, error};
use tokio::sync::mpsc;
use crate::topology::{SharedTopology, TopologyGraph};
use std::sync::{Arc, Mutex};
#[cfg(feature = "pcap")]
use etherparse::PacketHeaders;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[cfg(feature = "pcap")]
use pcap::{Capture, Device};

pub struct PacketEngine {
    #[cfg(feature = "pcap")]
    capture: Capture<pcap::Active>,
    topology: SharedTopology,
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

        Ok(Self { 
            capture,
            topology: Arc::new(Mutex::new(TopologyGraph::new())),
        })
    }

    pub fn get_topology(&self) -> SharedTopology {
        self.topology.clone()
    }

    pub fn set_filter(&mut self, filter: &str) -> Result<()> {
        self.capture.filter(filter, true)?;
        Ok(())
    }

    pub fn next_packet(&mut self) -> Result<Option<String>> {
        match self.capture.next_packet() {
            Ok(packet) => {
                match PacketHeaders::from_ethernet_slice(&packet.data) {
                    Ok(headers) => {
                        let mut desc = String::new();
                        
                        // IP Layer
                        if let Some(net) = headers.net {
                            match net {
                                etherparse::NetHeaders::Ipv4(ipv4, _) => {
                                    let src = std::net::Ipv4Addr::from(ipv4.source).to_string();
                                    let dst = std::net::Ipv4Addr::from(ipv4.destination).to_string();
                                    
                                    desc.push_str(&format!("{} -> {} ", src, dst));

                                    // Discovery Logic
                                    if let Ok(mut graph) = self.topology.lock() {
                                        graph.add_node(src.clone(), src.clone(), "host".to_string());
                                        graph.add_node(dst.clone(), dst.clone(), "host".to_string());
                                        graph.add_edge(src, dst);
                                    }
                                }
                                etherparse::NetHeaders::Ipv6(ipv6, _) => {
                                    let src = format!("{:?}", ipv6.source);
                                    let dst = format!("{:?}", ipv6.destination);
                                    desc.push_str(&format!("{} -> {} ", src, dst));

                                    if let Ok(mut graph) = self.topology.lock() {
                                        graph.add_node(src.clone(), src.clone(), "host".to_string());
                                        graph.add_node(dst.clone(), dst.clone(), "host".to_string());
                                        graph.add_edge(src, dst);
                                    }
                                }
                            }
                        }

                        // Transport Layer
                        if let Some(transport) = headers.transport {
                            match transport {
                                etherparse::TransportHeader::Tcp(tcp) => {
                                    desc.push_str(&format!("[TCP] {}:{} -> {}:{}", 
                                        "", tcp.source_port, "", tcp.destination_port));
                                }
                                etherparse::TransportHeader::Udp(udp) => {
                                    desc.push_str(&format!("[UDP] {}:{} -> {}:{}", 
                                        "", udp.source_port, "", udp.destination_port));
                                }
                                _ => desc.push_str("[OTHER]"),
                            }
                        }

                        if desc.is_empty() {
                            Ok(Some(format!("Packet: {} bytes", packet.header.len)))
                        } else {
                            Ok(Some(desc))
                        }
                    }
                    Err(_) => Ok(Some(format!("Unknown Packet: {} bytes", packet.header.len))),
                }
            }
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }


    pub fn spawn_loop(mut self, tx: mpsc::Sender<String>) {
        tokio::task::spawn_blocking(move || {
            loop {
                match self.next_packet() {
                    Ok(Some(desc)) => {
                        if tx.blocking_send(desc).is_err() {
                            break;
                        }
                    }
                    Ok(None) => continue, 
                    Err(e) => {
                        error!("Capture engine error: {}", e);
                        break;
                    }
                }
            }
        });
    }

    pub fn spawn_remote_loop(mut self, server_addr: String) {
        let (tx, mut rx) = mpsc::channel::<String>(100);
        
        // Blocking capture loop
        tokio::task::spawn_blocking(move || {
            loop {
                match self.next_packet() {
                    Ok(Some(desc)) => {
                        if tx.blocking_send(desc).is_err() {
                            break;
                        }
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        error!("Capture engine error: {}", e);
                        break;
                    }
                }
            }
        });

        // Async streaming loop
        tokio::spawn(async move {
            let token = netsage_auth::get_local_token();
            loop {
                info!("Connecting to central NetSage server at {}...", server_addr);
                match TcpStream::connect(&server_addr).await {
                    Ok(mut stream) => {
                        info!("Connected to server. Starting remote stream.");
                        while let Some(desc) = rx.recv().await {
                            let pkt = ingestion::IngestionPacket {
                                auth: token.clone(),
                                payload: desc,
                            };
                            if let Ok(data) = serde_json::to_string(&pkt) {
                                let data = format!("{}\n", data);
                                if let Err(e) = stream.write_all(data.as_bytes()).await {
                                    error!("Failed to send packet data to server: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to connect to NetSage server ({}). Retrying in 5s...", e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }
}
