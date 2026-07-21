use crate::tools::ToolRegistry;
use anyhow::{anyhow, Result};
use std::sync::Arc;

/// The attack planner is responsible for orchestrating AI-driven attack plans.
pub struct AttackPlanner {
    tool_registry: Arc<ToolRegistry>,
}

impl AttackPlanner {
    /// Creates a new `AttackPlanner` given a tool registry.
    pub fn new(tool_registry: Arc<ToolRegistry>) -> Self {
        Self { tool_registry }
    }

    /// Plans an attack path against the specified target domain.
    pub async fn plan_attack_path(&self, target_domain: &str) -> Result<Vec<String>> {
        if target_domain.trim().is_empty() {
            return Err(anyhow!("Target domain cannot be empty"));
        }

        let mut plan = Vec::new();
        plan.push(format!(
            "Reconnaissance: Port scan and service discovery on target {target_domain}"
        ));

        let available_tools = self.tool_registry.all();
        let tool_names: Vec<&str> = available_tools.iter().map(|t| t.name()).collect();

        if tool_names.contains(&"port_scan") || tool_names.contains(&"scan") {
            plan.push(format!("Active Scanning: Execute network scan against {target_domain}"));
        }

        if tool_names.contains(&"smb_enum") || tool_names.contains(&"ldap_enum") {
            plan.push(
                "Enumeration: Enumerate SMB shares and Active Directory LDAP directory".to_string(),
            );
        }

        if tool_names.contains(&"kerberoast") || tool_names.contains(&"asreproast") {
            plan.push(
                "Credential Harvesting: Perform Kerberoasting and AS-REP roasting".to_string(),
            );
        }

        if tool_names.contains(&"execute_module") {
            plan.push(
                "Module Execution: Run privilege escalation and lateral movement modules"
                    .to_string(),
            );
        }

        // Standard operational phases
        plan.push(
            "Vulnerability Analysis: Identify misconfigurations and vulnerable services"
                .to_string(),
        );
        plan.push(
            "Exploitation & Credential Extraction: Extract cached hashes and plaintext credentials"
                .to_string(),
        );
        plan.push(format!(
            "Privilege Escalation & Pivoting: Pivot to Domain Controller of {target_domain}"
        ));

        Ok(plan)
    }

    /// Returns a reference to the inner tool registry.
    pub fn tool_registry(&self) -> &Arc<ToolRegistry> {
        &self.tool_registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_attack_planner_empty_target() {
        let registry = Arc::new(ToolRegistry::new());
        let planner = AttackPlanner::new(registry);
        assert!(planner.plan_attack_path("").await.is_err());
    }

    #[tokio::test]
    async fn test_attack_planner_generates_plan() {
        let registry = Arc::new(ToolRegistry::new());
        let planner = AttackPlanner::new(registry);
        let plan = planner.plan_attack_path("corp.local").await.unwrap();
        assert!(!plan.is_empty());
        assert!(plan[0].contains("corp.local"));
    }
}
