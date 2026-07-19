//! AI Module for nxc-rs
//!
//! This crate provides AI-driven capabilities for network execution, including
//! automated attack path generation, agent planning, and attack graph modeling.

pub mod agent;
pub mod attack_graph;
pub mod planner;
pub mod providers;
pub mod tools;

pub use agent::AiAgent;
pub use attack_graph::{AttackEdge, AttackGraph, AttackNode};
pub use planner::AttackPlanner;
pub use providers::gemini::GeminiProvider;
pub use tools::{
    db::QueryDbTool, modules::SearchModulesTool, protocol::ProtocolTool, scan::ScanTool,
    utils::UtilityTool, ToolRegistry,
};
