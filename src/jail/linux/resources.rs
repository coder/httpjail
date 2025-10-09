use crate::sys_resource::SystemResource;
use anyhow::{Context, Result};
use std::future::Future;
use tracing::debug;

/// Run async code, using current tokio runtime if available or creating a new one
fn block_on<F: Future + Send + 'static>(future: F) -> F::Output
where
    F::Output: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // We're in a tokio runtime - use spawn_blocking to avoid nested runtime issues
            std::thread::spawn(move || {
                tokio::runtime::Runtime::new()
                    .expect("Failed to create tokio runtime")
                    .block_on(future)
            })
            .join()
            .expect("Thread panicked")
        }
        Err(_) => {
            // No runtime, create a new one
            tokio::runtime::Runtime::new()
                .expect("Failed to create tokio runtime")
                .block_on(future)
        }
    }
}

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

        // Use netlink-based implementation instead of `ip` command
        super::netlink::create_netns(&name)
            .context("Failed to create network namespace via netlink")?;

        Ok(Self {
            name,
            created: true,
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        super::netlink::delete_netns(&self.name).context("Failed to delete network namespace")?;

        self.created = false;
        Ok(())
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

        // Use netlink-based implementation
        let host_clone = host_name.clone();
        let ns_clone = ns_name.clone();
        block_on(async move { super::netlink::create_veth_pair(&host_clone, &ns_clone).await })
            .context("Failed to create veth pair via netlink")?;

        debug!("Created veth pair: {} <-> {}", host_name, ns_name);
        Ok(Self {
            host_name,
            ns_name,
            created: true,
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        // Deleting the host side will automatically delete both ends
        let host_name = self.host_name.clone();
        let _ = block_on(async move { super::netlink::delete_link(&host_name).await });

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

/// NFTable resource wrapper for a jail
pub struct NFTable {
    #[allow(dead_code)]
    jail_id: String,
    table: Option<super::nftables::NFTable>,
}

impl NFTable {
    #[allow(dead_code)]
    pub fn set_table(&mut self, table: super::nftables::NFTable) {
        self.table = Some(table);
    }
}

impl SystemResource for NFTable {
    fn create(jail_id: &str) -> Result<Self> {
        // Table is created separately via set_table
        Ok(Self {
            jail_id: jail_id.to_string(),
            table: None,
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        // Table cleans itself up via Drop trait
        self.table = None;
        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        // Create wrapper for existing table (will be cleaned up on drop)
        let table = super::nftables::NFTable::for_existing(jail_id, false);
        Self {
            jail_id: jail_id.to_string(),
            table: Some(table),
        }
    }
}
