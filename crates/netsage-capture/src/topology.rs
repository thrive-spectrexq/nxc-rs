use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct Edge {
    pub from: String,
    pub to: String,
}

pub struct TopologyGraph {
    pub nodes: HashMap<String, Node>,
    pub edges: HashSet<(String, String)>,
}

impl TopologyGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashSet::new(),
        }
    }

    pub fn add_node(&mut self, id: String, label: String) {
        self.nodes.insert(id.clone(), Node { id, label });
    }

    pub fn add_edge(&mut self, from: String, to: String) {
        self.edges.insert((from, to));
    }

    pub fn to_ascii(&self) -> String {
        let mut output = String::new();
        output.push_str("Discovered Network Topology:\n\n");
        for (from, to) in &self.edges {
            let from_label = self.nodes.get(from).map(|n| &n.label).unwrap_or(from);
            let to_label = self.nodes.get(to).map(|n| &n.label).unwrap_or(to);
            output.push_str(&format!("  {} <---> {}\n", from_label, to_label));
        }
        if self.edges.is_empty() {
            output.push_str("  (No connections discovered yet)");
        }
        output
    }
}
