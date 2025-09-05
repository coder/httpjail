use crate::sys_resource::SystemResource;
use anyhow::{Context, Result};
use std::process::Command;
use tracing::{debug, info};

/// Network namespace resource
pub struct NetworkNamespace {
    name: String,
    created: bool,
}

impl NetworkNamespace {
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl SystemResource for NetworkNamespace {
    fn create(jail_id: &str) -> Result<Self> {
        let name = format!("httpjail_{}", jail_id);

        let output = Command::new("ip")
            .args(["netns", "add", &name])
            .output()
            .context("Failed to execute ip netns add")?;

        if output.status.success() {
            info!("Created network namespace: {}", name);
            Ok(Self {
                name,
                created: true,
            })
        } else {
            anyhow::bail!(
                "Failed to create namespace {}: {}",
                name,
                String::from_utf8_lossy(&output.stderr)
            )
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        let output = Command::new("ip")
            .args(["netns", "del", &self.name])
            .output()
            .context("Failed to execute ip netns del")?;

        if output.status.success() {
            debug!("Deleted network namespace: {}", self.name);
            self.created = false;
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such file") || stderr.contains("Cannot find") {
                // Already deleted
                self.created = false;
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to delete namespace: {}", stderr))
            }
        }
    }

    fn for_existing(jail_id: &str) -> Self {
        Self {
            name: format!("httpjail_{}", jail_id),
            created: true, // Assume it exists for cleanup
        }
    }
}

/// Virtual ethernet pair resource
pub struct VethPair {
    host_name: String,
    #[allow(dead_code)]
    ns_name: String,
    created: bool,
}

impl VethPair {
    #[allow(dead_code)]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    #[allow(dead_code)]
    pub fn ns_name(&self) -> &str {
        &self.ns_name
    }
}

impl SystemResource for VethPair {
    fn create(jail_id: &str) -> Result<Self> {
        // Use shortened names to fit within 15 char limit
        let host_name = format!("vh_{}", jail_id);
        let ns_name = format!("vn_{}", jail_id);

        let output = Command::new("ip")
            .args([
                "link", "add", &host_name, "type", "veth", "peer", "name", &ns_name,
            ])
            .output()
            .context("Failed to create veth pair")?;

        if output.status.success() {
            debug!("Created veth pair: {} <-> {}", host_name, ns_name);
            Ok(Self {
                host_name,
                ns_name,
                created: true,
            })
        } else {
            anyhow::bail!(
                "Failed to create veth pair: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        // Deleting the host side will automatically delete both ends
        let _ = Command::new("ip")
            .args(["link", "del", &self.host_name])
            .output();

        self.created = false;
        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        Self {
            host_name: format!("vh_{}", jail_id),
            ns_name: format!("vn_{}", jail_id),
            created: true,
        }
    }
}

/// Namespace configuration directory (/etc/netns/<namespace>)
pub struct NamespaceConfig {
    path: String,
    created: bool,
}

impl SystemResource for NamespaceConfig {
    fn create(jail_id: &str) -> Result<Self> {
        let namespace_name = format!("httpjail_{}", jail_id);
        let path = format!("/etc/netns/{}", namespace_name);

        // Create directory if needed
        if !std::path::Path::new(&path).exists() {
            std::fs::create_dir_all(&path)
                .context("Failed to create namespace config directory")?;
            debug!("Created namespace config directory: {}", path);
        }

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
            if let Err(e) = std::fs::remove_dir_all(&self.path) {
                // Log but don't fail
                debug!("Failed to remove namespace config directory: {}", e);
            } else {
                debug!("Removed namespace config directory: {}", self.path);
            }
        }

        self.created = false;
        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        let namespace_name = format!("httpjail_{}", jail_id);
        Self {
            path: format!("/etc/netns/{}", namespace_name),
            created: true,
        }
    }
}

/// Collection of iptables rules for a jail
pub struct IPTablesRules {
    #[allow(dead_code)]
    jail_id: String,
    rules: Vec<super::iptables::IPTablesRule>,
}

impl IPTablesRules {
    #[allow(dead_code)]
    pub fn new(jail_id: String) -> Self {
        Self {
            jail_id,
            rules: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn add_rule(&mut self, rule: super::iptables::IPTablesRule) {
        self.rules.push(rule);
    }

    #[allow(dead_code)]
    pub fn comment(&self) -> String {
        format!("httpjail-httpjail_{}", self.jail_id)
    }
}

impl SystemResource for IPTablesRules {
    fn create(jail_id: &str) -> Result<Self> {
        // Rules are added separately, not during creation
        Ok(Self {
            jail_id: jail_id.to_string(),
            rules: Vec::new(),
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        // Rules clean themselves up on drop
        self.rules.clear();
        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        use super::LINUX_NS_SUBNET;
        use super::iptables::IPTablesRule;

        let namespace_name = format!("httpjail_{}", jail_id);
        let comment = format!("httpjail-{}", namespace_name);

        // Create temporary IPTablesRule objects for cleanup
        // Their Drop impl will remove the rules
        let rules = vec![
            // MASQUERADE rule
            IPTablesRule::new_existing(
                Some("nat"),
                "POSTROUTING",
                vec![
                    "-s",
                    LINUX_NS_SUBNET,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "MASQUERADE",
                ],
            ),
            // FORWARD source rule
            IPTablesRule::new_existing(
                None,
                "FORWARD",
                vec![
                    "-s",
                    LINUX_NS_SUBNET,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "ACCEPT",
                ],
            ),
            // FORWARD destination rule
            IPTablesRule::new_existing(
                None,
                "FORWARD",
                vec![
                    "-d",
                    LINUX_NS_SUBNET,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "ACCEPT",
                ],
            ),
        ];

        Self {
            jail_id: jail_id.to_string(),
            rules,
        }
    }
}
