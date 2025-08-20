use super::{Jail, JailConfig};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

const PF_ANCHOR_NAME: &str = "httpjail";
const GROUP_NAME: &str = "httpjail";

pub struct MacOSJail {
    config: JailConfig,
    group_gid: Option<u32>,
    pf_rules_path: String,
}

impl MacOSJail {
    pub fn new(config: JailConfig) -> Result<Self> {
        let pf_rules_path = format!("/tmp/{}.pf", config.jail_name);
        
        Ok(Self {
            config,
            group_gid: None,
            pf_rules_path,
        })
    }
    
    /// Get or create the httpjail group
    fn ensure_group(&mut self) -> Result<u32> {
        // Check if group already exists
        let output = Command::new("dscl")
            .args(&[".", "-read", &format!("/Groups/{}", GROUP_NAME), "PrimaryGroupID"])
            .output()
            .context("Failed to check group existence")?;
        
        if output.status.success() {
            // Parse GID from output
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = stdout.lines().find(|l| l.contains("PrimaryGroupID")) {
                if let Some(gid_str) = line.split_whitespace().last() {
                    let gid = gid_str.parse::<u32>()
                        .context("Failed to parse GID")?;
                    info!("Using existing group {} with GID {}", GROUP_NAME, gid);
                    self.group_gid = Some(gid);
                    return Ok(gid);
                }
            }
        }
        
        // Create group if it doesn't exist
        info!("Creating group {}", GROUP_NAME);
        let output = Command::new("sudo")
            .args(&["dseditgroup", "-o", "create", GROUP_NAME])
            .output()
            .context("Failed to create group")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to create group: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        // Get the newly created group's GID
        let output = Command::new("dscl")
            .args(&[".", "-read", &format!("/Groups/{}", GROUP_NAME), "PrimaryGroupID"])
            .output()
            .context("Failed to read group GID")?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().find(|l| l.contains("PrimaryGroupID")) {
            if let Some(gid_str) = line.split_whitespace().last() {
                let gid = gid_str.parse::<u32>()
                    .context("Failed to parse GID")?;
                info!("Created group {} with GID {}", GROUP_NAME, gid);
                self.group_gid = Some(gid);
                return Ok(gid);
            }
        }
        
        anyhow::bail!("Failed to get GID for group {}", GROUP_NAME)
    }
    
    /// Create PF rules for traffic diversion
    fn create_pf_rules(&self, gid: u32) -> Result<String> {
        let rules = format!(
            r#"# httpjail PF rules
# Divert HTTP traffic (port 80) from httpjail group to local HTTP proxy
pass out proto tcp from any to any port 80 group {} divert-to 127.0.0.1 port {} no state

# Divert HTTPS traffic (port 443) from httpjail group to local HTTPS proxy
pass out proto tcp from any to any port 443 group {} divert-to 127.0.0.1 port {} no state

# Allow proxy to receive diverted connections
pass in on lo0 proto tcp to 127.0.0.1 port {} no state
pass in on lo0 proto tcp to 127.0.0.1 port {} no state

# Allow proxy to make outbound connections
pass out proto tcp from 127.0.0.1 to any keep state
"#,
            gid,
            self.config.http_proxy_port,
            gid,
            self.config.https_proxy_port,
            self.config.http_proxy_port,
            self.config.https_proxy_port
        );
        
        Ok(rules)
    }
    
    /// Load PF rules into an anchor
    fn load_pf_rules(&self, rules: &str) -> Result<()> {
        // Write rules to temp file
        fs::write(&self.pf_rules_path, rules)
            .context("Failed to write PF rules file")?;
        
        // Load rules into anchor
        info!("Loading PF rules from {}", self.pf_rules_path);
        let output = Command::new("sudo")
            .args(&["pfctl", "-a", PF_ANCHOR_NAME, "-f", &self.pf_rules_path])
            .output()
            .context("Failed to load PF rules")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to load PF rules: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        // Enable PF if not already enabled
        let _ = Command::new("sudo")
            .args(&["pfctl", "-E"])
            .output();
        
        info!("PF rules loaded successfully");
        Ok(())
    }
    
    /// Remove PF rules from anchor
    fn unload_pf_rules(&self) -> Result<()> {
        info!("Removing PF rules from anchor {}", PF_ANCHOR_NAME);
        
        // Flush the anchor
        let output = Command::new("sudo")
            .args(&["pfctl", "-a", PF_ANCHOR_NAME, "-F", "all"])
            .output()
            .context("Failed to flush PF anchor")?;
        
        if !output.status.success() {
            warn!("Failed to flush PF anchor: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        // Clean up temp file
        if Path::new(&self.pf_rules_path).exists() {
            fs::remove_file(&self.pf_rules_path)
                .context("Failed to remove PF rules file")?;
        }
        
        Ok(())
    }
}

impl Jail for MacOSJail {
    fn init(&self) -> Result<()> {
        // Check if we have sudo access
        let output = Command::new("sudo")
            .args(&["-n", "true"])
            .output()
            .context("Failed to check sudo access")?;
        
        if !output.status.success() {
            anyhow::bail!("This tool requires sudo access. Please run with sudo or authenticate first.");
        }
        
        // Check if PF is available
        let output = Command::new("pfctl")
            .args(&["-s", "info"])
            .output()
            .context("Failed to check PF availability")?;
        
        if !output.status.success() {
            anyhow::bail!("PF (Packet Filter) is not available on this system");
        }
        
        Ok(())
    }
    
    fn setup(&self, _proxy_port: u16) -> Result<()> {
        let mut jail = self.clone();
        // Note: _proxy_port parameter is kept for interface compatibility
        // but we use the configured ports from JailConfig
        
        // Ensure group exists and get GID
        let gid = jail.ensure_group()?;
        
        // Create and load PF rules
        let rules = jail.create_pf_rules(gid)?;
        jail.load_pf_rules(&rules)?;
        
        info!("Jail setup complete with HTTP proxy on port {} and HTTPS proxy on port {}", 
              jail.config.http_proxy_port, jail.config.https_proxy_port);
        Ok(())
    }
    
    fn execute(&self, command: &[String]) -> Result<ExitStatus> {
        if command.is_empty() {
            anyhow::bail!("No command specified");
        }
        
        let gid = self.group_gid
            .ok_or_else(|| anyhow::anyhow!("Group not initialized. Call setup() first"))?;
        
        debug!("Executing command with jail GID {}: {:?}", gid, command);
        
        // Use newgrp to add the supplemental group and execute command
        // Format: newgrp httpjail -c "command args..."
        let command_str = command.join(" ");
        
        let mut cmd = Command::new("sudo");
        cmd.arg("-E")  // Preserve environment
            .arg("sg")  // Use sg (similar to newgrp but better for scripts)
            .arg(GROUP_NAME)
            .arg("-c")
            .arg(&command_str);
        
        let status = cmd.status()
            .context("Failed to execute command with jail")?;
        
        Ok(status)
    }
    
    fn cleanup(&self) -> Result<()> {
        self.unload_pf_rules()?;
        info!("Jail cleanup complete");
        Ok(())
    }
}

impl Clone for MacOSJail {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            group_gid: self.group_gid,
            pf_rules_path: self.pf_rules_path.clone(),
        }
    }
}