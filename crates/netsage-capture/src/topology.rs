use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub label: String,
    pub node_type: String, // "host", "gateway", "service"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub metadata: HashMap<String, String>, // e.g., "latency" -> "2ms", "throughput" -> "50Mbps"
}

pub struct TopologyGraph {
    pub nodes: HashMap<String, Node>,
    pub edges: Vec<Edge>,
}

impl TopologyGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, id: String, label: String, node_type: String) {
        self.nodes.insert(
            id.clone(),
            Node {
                id,
                label,
                node_type,
            },
        );
    }

    pub fn add_edge(&mut self, from: String, to: String) {
        if from != to
            && !self
                .edges
                .iter()
                .any(|e| (e.from == from && e.to == to) || (e.from == to && e.to == from))
        {
            self.edges.push(Edge {
                from,
                to,
                metadata: HashMap::new(),
            });
        }
    }

    pub fn update_edge_metadata(&mut self, from: &str, to: &str, key: String, value: String) {
        if let Some(edge) = self
            .edges
            .iter_mut()
            .find(|e| (e.from == from && e.to == to) || (e.from == to && e.to == from))
        {
            edge.metadata.insert(key, value);
        }
    }

    pub fn to_ascii(&self) -> String {
        let mut output = String::new();
        output.push_str("Discovered Network Topology:\n\n");

        if self.nodes.is_empty() {
            output.push_str("  (No nodes discovered yet)\n");
            return output;
        }

        // Simple tree-like representation for discovery
        let mut seen = HashSet::new();
        for (id, node) in &self.nodes {
            if seen.contains(id) {
                continue;
            }
            output.push_str(&format!(
                "  [{}] {}\n",
                node.node_type.to_uppercase(),
                node.label
            ));
            seen.insert(id.clone());

            for edge in &self.edges {
                if &edge.from == id {
                    let to_node = self
                        .nodes
                        .get(&edge.to)
                        .map(|n| format!("[{}] {}", n.node_type.to_uppercase(), n.label))
                        .unwrap_or_else(|| edge.to.clone());

                    let mut meta_str = String::new();
                    if !edge.metadata.is_empty() {
                        meta_str = format!(
                            " ({})",
                            edge.metadata
                                .iter()
                                .map(|(k, v)| format!("{}: {}", k, v))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }

                    output.push_str(&format!("    └──► {}{}\n", to_node, meta_str));
                    seen.insert(edge.to.clone());
                }
            }
        }

        output
    }

    pub fn to_mermaid(&self) -> String {
        let mut output = String::from("graph TD\n");
        for node in self.nodes.values() {
            let label = node.label.replace('"', "'");
            let node_id = node.id.replace('.', "_");
            let style = match node.node_type.as_str() {
                "gateway" => ":::gateway",
                "service" => ":::service",
                _ => "",
            };
            output.push_str(&format!("    {}[(\"{}\")]{}\n", node_id, label, style));
        }

        for edge in &self.edges {
            let from_id = edge.from.replace('.', "_");
            let to_id = edge.to.replace('.', "_");

            let mut meta_str = String::new();
            if !edge.metadata.is_empty() {
                meta_str = format!(
                    "|{}|",
                    edge.metadata
                        .iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            output.push_str(&format!("    {} -- {} --> {}\n", from_id, meta_str, to_id));
        }

        output.push_str("\n    classDef gateway fill:#f96,stroke:#333,stroke-width:2px;\n");
        output.push_str("    classDef service fill:#69f,stroke:#333,stroke-width:2px;\n");

        output
    }
}

pub type SharedTopology = Arc<Mutex<TopologyGraph>>;
