use anyhow::{Context, Result};
use std::process::Command;
use tracing::{debug, error, warn};

/// RAII wrapper for iptables rules that ensures cleanup on drop
#[derive(Debug)]
pub struct IPTablesRule {
    /// The table (e.g., "nat", "filter")
    table: Option<String>,
    /// The chain (e.g., "FORWARD", "POSTROUTING")
    chain: String,
    /// The full rule specification (everything after -A/-I CHAIN)
    rule_spec: Vec<String>,
    /// Whether the rule was successfully added
    added: bool,
}

impl IPTablesRule {
    /// Create a rule object for an existing rule (for cleanup purposes)
    /// This doesn't add the rule, but will remove it when dropped
    pub fn new_existing(table: Option<&str>, chain: &str, rule_spec: Vec<&str>) -> Self {
        Self {
            table: table.map(|s| s.to_string()),
            chain: chain.to_string(),
            rule_spec: rule_spec.iter().map(|s| s.to_string()).collect(),
            added: true, // Mark as added so it will be removed on drop
        }
    }

    /// Create and add a new iptables rule
    pub fn new(table: Option<&str>, chain: &str, rule_spec: Vec<&str>) -> Result<Self> {
        let mut args = Vec::new();

        // Add table specification if provided
        if let Some(t) = table {
            args.push("-t".to_string());
            args.push(t.to_string());
        }

        // Add chain and action (we use -I for insert at top)
        args.push("-I".to_string());
        args.push(chain.to_string());
        args.push("1".to_string()); // Insert at position 1

        // Add the rule specification
        let rule_spec_owned: Vec<String> = rule_spec.iter().map(|s| s.to_string()).collect();
        args.extend(rule_spec_owned.clone());

        // Execute iptables command
        let output = Command::new("iptables")
            .args(&args)
            .output()
            .context("Failed to execute iptables")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Check if rule already exists (not an error)
            if !stderr.contains("File exists") {
                anyhow::bail!("Failed to add iptables rule: {}", stderr);
            }
        }

        debug!(
            "Added iptables rule: {} {} {}",
            table.unwrap_or("filter"),
            chain,
            rule_spec_owned.join(" ")
        );

        Ok(Self {
            table: table.map(|s| s.to_string()),
            chain: chain.to_string(),
            rule_spec: rule_spec_owned,
            added: true,
        })
    }

    /// Remove the iptables rule
    fn remove(&self) -> Result<()> {
        if !self.added {
            return Ok(());
        }

        let mut args = Vec::new();

        // Add table specification if provided
        if let Some(ref t) = self.table {
            args.push("-t".to_string());
            args.push(t.clone());
        }

        // Delete action
        args.push("-D".to_string());
        args.push(self.chain.clone());

        // Add the rule specification
        args.extend(self.rule_spec.clone());

        // Execute iptables command
        let output = Command::new("iptables")
            .args(&args)
            .output()
            .context("Failed to execute iptables")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore if rule doesn't exist (already removed)
            if !stderr.contains("No such file") && !stderr.contains("does a matching rule exist") {
                warn!("Failed to remove iptables rule: {}", stderr);
            }
        } else {
            debug!(
                "Removed iptables rule: {} {} {}",
                self.table.as_deref().unwrap_or("filter"),
                self.chain,
                self.rule_spec.join(" ")
            );
        }

        Ok(())
    }
}

impl Drop for IPTablesRule {
    fn drop(&mut self) {
        if self.added {
            if let Err(e) = self.remove() {
                error!("Failed to remove iptables rule on drop: {}", e);
            }
            self.added = false;
        }
    }
}
