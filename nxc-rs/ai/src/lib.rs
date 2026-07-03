//! AI Module for nxc-rs
//! 
//! This crate provides AI-driven capabilities for network execution, including
//! automated attack path generation, agent planning, and attack graph modeling.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::uninlined_format_args,
    clippy::redundant_closure
)]

pub mod agent;
pub mod providers;
pub mod tools;
pub mod planner;
pub mod attack_graph;

pub use agent::AiAgent;
pub use providers::gemini::GeminiProvider;
pub use tools::{
    db::QueryDbTool, modules::SearchModulesTool, protocol::ProtocolTool, scan::ScanTool,
    utils::UtilityTool, ToolRegistry,
};
pub use planner::AttackPlanner;
pub use attack_graph::{AttackGraph, AttackNode, AttackEdge};
