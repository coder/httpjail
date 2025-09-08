use crate::sys_resource::SystemResource;
use anyhow::{Context, Result};
use std::process::Command;
use tracing::{debug, info, warn};

/// macOS user group resource
pub struct MacOSGroup {
    name: String,
    #[allow(dead_code)]
    gid: Option<u32>,
    created: bool,
}

impl MacOSGroup {
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[allow(dead_code)]
    pub fn gid(&self) -> Option<u32> {
        self.gid
    }
}

impl SystemResource for MacOSGroup {
    fn create(jail_id: &str) -> Result<Self> {
        let name = format!("httpjail_{}", jail_id);

        // Create the group
        let output = Command::new("dseditgroup")
            .args(["-o", "create", &name])
            .output()
            .context("Failed to execute dseditgroup create")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to create group {}: {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        info!("Created macOS group: {}", name);

        // Get the GID of the created group
        let output = Command::new("dscl")
            .args([".", "-read", &format!("/Groups/{}", name), "PrimaryGroupID"])
            .output()
            .context("Failed to read group GID")?;

        let gid = if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout
                .lines()
                .find(|line| line.starts_with("PrimaryGroupID:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|gid_str| gid_str.parse::<u32>().ok())
        } else {
            None
        };

        Ok(Self {
            name,
            gid,
            created: true,
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        let output = Command::new("dseditgroup")
            .args(["-o", "delete", &self.name])
            .output()
            .context("Failed to execute dseditgroup delete")?;

        if output.status.success() {
            debug!("Deleted macOS group: {}", self.name);
            self.created = false;
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Group not found") {
                self.created = false;
            } else {
                warn!("Failed to delete group {}: {}", self.name, stderr);
            }
        }

        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        Self {
            name: format!("httpjail_{}", jail_id),
            gid: None,
            created: true,
        }
    }
}

/// PF anchor resource
pub struct PfAnchor {
    name: String,
    created: bool,
}

impl PfAnchor {
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl SystemResource for PfAnchor {
    fn create(jail_id: &str) -> Result<Self> {
        // Use an anchor path under com.apple/* so it's included by the default pf rules
        // and we don't need to rewrite the main ruleset.
        let name = format!("com.apple/httpjail/{}", jail_id);

        // Anchors are created when rules are loaded
        // We just track the name here
        Ok(Self {
            name,
            created: true,
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        // Flush all rules from the anchor
        let output = Command::new("pfctl")
            .args(["-a", &self.name, "-F", "all"])
            .output()
            .context("Failed to flush PF anchor")?;

        if output.status.success() {
            debug!("Flushed PF anchor: {}", self.name);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Log but don't fail - anchor might not exist
            debug!("Could not flush PF anchor {}: {}", self.name, stderr);
        }

        self.created = false;
        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        Self {
            name: format!("com.apple/httpjail/{}", jail_id),
            created: true,
        }
    }
}

/// PF rules file resource
pub struct PfRulesFile {
    path: String,
    created: bool,
}

impl PfRulesFile {
    #[allow(dead_code)]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[allow(dead_code)]
    pub fn write_rules(&self, content: &str) -> Result<()> {
        std::fs::write(&self.path, content).context("Failed to write PF rules file")
    }
}

impl SystemResource for PfRulesFile {
    fn create(jail_id: &str) -> Result<Self> {
        let path = format!("/tmp/httpjail_{}.pf", jail_id);

        Ok(Self {
            path,
            created: true,
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        if std::path::Path::new(&self.path).exists() {
            if let Err(e) = std::fs::remove_file(&self.path) {
                debug!("Failed to remove PF rules file: {}", e);
            } else {
                debug!("Removed PF rules file: {}", self.path);
            }
        }

        self.created = false;
        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        Self {
            path: format!("/tmp/httpjail_{}.pf", jail_id),
            created: true,
        }
    }
}
