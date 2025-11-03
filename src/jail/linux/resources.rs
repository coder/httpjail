use crate::sys_resource::SystemResource;
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info, warn};

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

/// /etc/netns/ resolv.conf resource for network namespace DNS configuration
///
/// # How it works
///
/// Uses Linux kernel's built-in /etc/netns/ mechanism. When a process enters
/// a network namespace via `ip netns exec`, the kernel automatically bind-mounts
/// files from /etc/netns/<namespace>/ over their corresponding paths.
///
/// # Symlinked /etc/resolv.conf handling
///
/// When /etc/resolv.conf is a symlink (common with systemd-resolved pointing to
/// /run/systemd/resolve/stub-resolv.conf), ip netns exec follows the symlink and
/// bind-mounts onto the target file. This requires:
///
/// 1. **Creation**: Ensure the symlink target exists on the host (we create an empty
///    placeholder in /run/systemd/resolve/ if needed - safe since /run is tmpfs)
/// 2. **Cleanup**: Explicitly unmount the bind-mount at the symlink target during
///    cleanup to prevent stale mounts from accumulating
///
/// # Safety
///
/// - Host's /etc/resolv.conf is never modified directly
/// - Placeholder creation is best-effort and won't affect systemd-resolved
/// - Cleanup unmounts are idempotent and won't fail if already unmounted
pub struct NetnsResolv {
    netns_dir: PathBuf,
    created: bool,
}

impl NetnsResolv {
    /// Resolve /etc/resolv.conf to its canonical path, handling symlinks
    ///
    /// Returns None if /etc/resolv.conf is not a symlink or cannot be resolved
    fn resolve_resolv_conf_target() -> Option<PathBuf> {
        let symlink_target = fs::read_link("/etc/resolv.conf").ok()?;

        // Convert relative path to absolute (e.g., "../run/systemd/resolve/stub-resolv.conf")
        let absolute_path = if symlink_target.is_absolute() {
            symlink_target
        } else {
            PathBuf::from("/etc").join(symlink_target)
        };

        fs::canonicalize(absolute_path).ok()
    }

    /// Create /etc/netns/httpjail_<id>/resolv.conf with specified nameserver
    pub fn create_with_nameserver(jail_id: &str, nameserver_ip: &str) -> Result<Self> {
        let netns_dir = PathBuf::from(format!("/etc/netns/httpjail_{}", jail_id));

        // Create directory and write resolv.conf
        fs::create_dir_all(&netns_dir)
            .with_context(|| format!("Failed to create {}", netns_dir.display()))?;

        let resolv_path = netns_dir.join("resolv.conf");
        fs::write(
            &resolv_path,
            format!("# httpjail managed\nnameserver {}\n", nameserver_ip),
        )
        .with_context(|| format!("Failed to write {}", resolv_path.display()))?;

        info!(
            "Created {} with nameserver {}",
            resolv_path.display(),
            nameserver_ip
        );

        // Ensure symlink target exists (see struct documentation for details)
        // Best-effort: ignore errors since the file might already exist or we lack permissions
        let _ = fs::create_dir_all("/run/systemd/resolve");
        let _ = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open("/run/systemd/resolve/stub-resolv.conf");

        debug!("Ensured /run/systemd/resolve/stub-resolv.conf exists");

        Ok(Self {
            netns_dir,
            created: true,
        })
    }
}

impl SystemResource for NetnsResolv {
    fn create(_jail_id: &str) -> Result<Self> {
        // NetnsResolv requires a nameserver IP parameter
        // Use create_with_nameserver instead
        anyhow::bail!("Use create_with_nameserver instead of create")
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        // Unmount bind-mount at symlink target (see struct documentation for why)
        // Best-effort: ignore failures since mount might already be cleaned up
        if let Some(target_path) = Self::resolve_resolv_conf_target() {
            let _ = Command::new("umount").arg(&target_path).output();
            debug!(
                "Attempted to unmount bind-mount at {}",
                target_path.display()
            );
        }

        // Remove /etc/netns/<namespace>/ directory
        match fs::remove_dir_all(&self.netns_dir) {
            Ok(()) => debug!("Removed {}", self.netns_dir.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("Failed to remove {}: {}", self.netns_dir.display(), e),
        }

        self.created = false;
        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        Self {
            netns_dir: PathBuf::from(format!("/etc/netns/httpjail_{}", jail_id)),
            created: true, // Assume it exists for cleanup
        }
    }
}
