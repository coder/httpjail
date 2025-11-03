pub mod dns;
mod nftables;
mod resources;

#[cfg(target_os = "linux")]
pub mod docker;

use super::Jail;
use super::JailConfig;
use crate::sys_resource::ManagedResource;
use anyhow::{Context, Result};
use resources::{NFTable, NetnsResolv, NetworkNamespace, VethPair};
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

// Linux namespace network configuration constants were previously fixed; the
// implementation now computes unique per‑jail subnets dynamically.

/// Format an IP address array as a string
pub fn format_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// Linux jail implementation using network namespaces
///
/// ## Architecture Overview
///
/// This jail creates an isolated network namespace where all traffic is transparently
/// redirected through our HTTP/HTTPS proxy. Unlike setting HTTP_PROXY environment variables,
/// this approach captures ALL network traffic, even from applications that don't respect
/// proxy settings.
///
/// ```
/// [Application in Namespace] ---> [nftables DNAT] ---> [Proxy on Host:HTTP/HTTPS]
///            |                                               |
///     (10.99.X.2)                                      (10.99.X.1)
///            |                                               |
///       [veth_ns] <------- veth pair --------> [veth_host on Host]
///            |                                               |
///      [Namespace]                                        [Host]
/// ```
///
/// ## Key Design Decisions
///
/// 1. **Network Namespace**: Complete isolation, no interference with host networking
/// 2. **veth Pair**: Virtual ethernet cable connecting namespace to host
/// 3. **Private IP Range**: Unique per-jail /30 within 10.99.0.0/16 (RFC1918)
/// 4. **nftables DNAT**: Transparent redirection without environment variables
/// 5. **DNS Override**: Handle systemd-resolved incompatibility with namespaces
///
/// ## Cleanup Guarantees
///
/// Resources are cleaned up in priority order:
/// 1. **Namespace deletion**: Automatically cleans up veth pair and namespace nftables rules
/// 2. **Host nftables table**: Atomic cleanup of entire table with all rules
/// 3. **Config directory**: /etc/netns/<namespace>/ removed if it exists
///
/// The namespace deletion is the critical cleanup - even if host nftables cleanup fails,
/// the jail is effectively destroyed once the namespace is gone.
///
/// Provides complete network isolation without persistent system state
pub struct LinuxJail {
    config: JailConfig,
    namespace: Option<ManagedResource<NetworkNamespace>>,
    veth_pair: Option<ManagedResource<VethPair>>,
    nftables: Option<ManagedResource<NFTable>>,
    netns_resolv: Option<ManagedResource<NetnsResolv>>,
    // Host-side DNS server for DNAT redirection
    host_dns_server: Option<dns::DummyDnsServer>,
    // Per-jail computed networking (unique /30 inside 10.99/16)
    host_ip: [u8; 4],
    host_cidr: String,
    guest_cidr: String,
    subnet_cidr: String,
}

impl LinuxJail {
    pub fn new(config: JailConfig) -> Result<Self> {
        let (host_ip, host_cidr, guest_cidr, subnet_cidr) =
            Self::compute_subnet_for_jail(&config.jail_id);
        Ok(Self {
            config,
            namespace: None,
            veth_pair: None,
            nftables: None,
            netns_resolv: None,
            host_dns_server: None,
            host_ip,
            host_cidr,
            guest_cidr,
            subnet_cidr,
        })
    }

    /// Check if running as root
    fn check_root() -> Result<()> {
        // Check UID directly using libc
        #[cfg(target_os = "linux")]
        let uid = unsafe { libc::getuid() };
        #[cfg(not(target_os = "linux"))]
        let uid = 1000; // Non-root UID for non-Linux platforms

        if uid != 0 {
            anyhow::bail!(
                "Network namespace operations require root access. Please run with sudo."
            );
        }
        Ok(())
    }

    /// Get the namespace name from the config
    fn namespace_name(&self) -> String {
        format!("httpjail_{}", self.config.jail_id)
    }

    /// Get the veth host interface name
    fn veth_host(&self) -> String {
        format!("vh_{}", self.config.jail_id)
    }

    /// Get the veth namespace interface name
    fn veth_ns(&self) -> String {
        format!("vn_{}", self.config.jail_id)
    }

    /// Compute a stable unique /30 in 10.99.0.0/16 for this jail
    /// There are 16384 possible /30 subnets in the /16.
    fn compute_subnet_for_jail(jail_id: &str) -> ([u8; 4], String, String, String) {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        jail_id.hash(&mut hasher);
        let h = hasher.finish();
        let idx = (h % 16384) as u32; // 0..16383
        let base = idx * 4; // network base offset within 10.99/16
        let third = ((base >> 8) & 0xFF) as u8;
        let fourth = (base & 0xFF) as u8;
        let network = [10u8, 99u8, third, fourth];
        let host_ip = [
            network[0],
            network[1],
            network[2],
            network[3].saturating_add(1),
        ];
        let guest_ip = [
            network[0],
            network[1],
            network[2],
            network[3].saturating_add(2),
        ];
        let host_cidr = format!("{}/30", format_ip(host_ip));
        let guest_cidr = format!("{}/30", format_ip(guest_ip));
        let subnet_cidr = format!("{}/30", format_ip(network));
        (host_ip, host_cidr, guest_cidr, subnet_cidr)
    }

    /// Expose the host veth IPv4 address for a given jail_id.
    /// This allows early binding of the proxy to the precise interface IP
    /// without falling back to 0.0.0.0.
    pub fn compute_host_ip_for_jail_id(jail_id: &str) -> [u8; 4] {
        let (host_ip, _host_cidr, _guest_cidr, _subnet_cidr) =
            Self::compute_subnet_for_jail(jail_id);
        host_ip
    }

    /// Create the network namespace using ManagedResource
    fn create_namespace(&mut self) -> Result<()> {
        self.namespace = Some(ManagedResource::<NetworkNamespace>::create(
            &self.config.jail_id,
        )?);
        info!("Created network namespace: {}", self.namespace_name());
        Ok(())
    }

    /// Set up veth pair for namespace connectivity using ManagedResource
    fn setup_veth_pair(&mut self) -> Result<()> {
        // Create veth pair
        self.veth_pair = Some(ManagedResource::<VethPair>::create(&self.config.jail_id)?);

        debug!(
            "Created veth pair: {} <-> {}",
            self.veth_host(),
            self.veth_ns()
        );

        // Move veth_ns end into the namespace
        let output = Command::new("ip")
            .args([
                "link",
                "set",
                &self.veth_ns(),
                "netns",
                &self.namespace_name(),
            ])
            .output()
            .context("Failed to move veth to namespace")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to move veth to namespace: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Configure networking inside the namespace
    fn configure_namespace_networking(&self) -> Result<()> {
        let namespace_name = self.namespace_name();
        let veth_ns = self.veth_ns();

        // Format the host IP once
        let host_ip = format_ip(self.host_ip);

        // Commands to run inside the namespace
        let commands = vec![
            // Bring up loopback
            vec!["ip", "link", "set", "lo", "up"],
            // Configure veth interface with IP
            vec!["ip", "addr", "add", &self.guest_cidr, "dev", &veth_ns],
            vec!["ip", "link", "set", &veth_ns, "up"],
            // Add default route pointing to host
            vec!["ip", "route", "add", "default", "via", &host_ip],
        ];

        for cmd_args in commands {
            let mut cmd = Command::new("ip");
            cmd.args(["netns", "exec", &namespace_name]);
            cmd.args(&cmd_args);

            debug!("Executing in namespace: {:?}", cmd);
            let output = cmd.output().context(format!(
                "Failed to execute: ip netns exec {} {:?}",
                namespace_name, cmd_args
            ))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!(
                    "Failed to configure namespace networking ({}): {}",
                    cmd_args.join(" "),
                    stderr
                );
            }
        }

        // Verify routes were added
        let mut verify_cmd = Command::new("ip");
        verify_cmd.args(["netns", "exec", &namespace_name, "ip", "route", "show"]);
        if let Ok(output) = verify_cmd.output() {
            let routes = String::from_utf8_lossy(&output.stdout);
            info!(
                "Routes in namespace {} after configuration:\n{}",
                namespace_name, routes
            );

            if !routes.contains(&host_ip) && !routes.contains("default") {
                warn!(
                    "WARNING: No route to host {} found in namespace. Network may not work properly.",
                    host_ip
                );
            }
        }

        debug!("Configured networking inside namespace {}", namespace_name);
        Ok(())
    }

    /// Configure host side of veth pair
    fn configure_host_networking(&self) -> Result<()> {
        let veth_host = self.veth_host();

        // Configure host side of veth
        let commands = vec![
            vec!["addr", "add", &self.host_cidr, "dev", &veth_host],
            vec!["link", "set", &veth_host, "up"],
        ];

        for cmd_args in commands {
            let output = Command::new("ip")
                .args(&cmd_args)
                .output()
                .context(format!("Failed to execute: ip {:?}", cmd_args))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Ignore "File exists" errors for IP addresses (might be from previous run)
                if !stderr.contains("File exists") {
                    anyhow::bail!(
                        "Failed to configure host networking (ip {}): {}",
                        cmd_args.join(" "),
                        stderr
                    );
                }
            }
        }

        // Enable IP forwarding for this interface
        let output = Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .output()
            .context("Failed to enable IP forwarding")?;

        if !output.status.success() {
            warn!(
                "Failed to enable IP forwarding: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        debug!("Configured host side networking for {}", veth_host);
        Ok(())
    }

    /// Add nftables rules inside the namespace for traffic redirection
    ///
    /// We use DNAT (Destination NAT) instead of REDIRECT for a critical reason:
    /// - REDIRECT changes the destination to 127.0.0.1 (localhost) within the namespace
    /// - Our proxy runs on the HOST, not inside the namespace
    /// - DNAT allows us to redirect to the host's IP address (10.99.X.1) where the proxy is actually listening
    /// - This is why we must use DNAT to 10.99.X.1:PORT instead of REDIRECT
    fn setup_namespace_nftables(&self) -> Result<()> {
        let namespace_name = self.namespace_name();
        let host_ip = format_ip(self.host_ip);

        // Create namespace-side nftables rules with DNS redirection
        let _table = nftables::NFTable::new_namespace_table_with_dns(
            &namespace_name,
            &host_ip,
            self.config.http_proxy_port,
            self.config.https_proxy_port,
            53, // DNS server port (unused but kept for API compatibility)
        )?;

        // The table will be cleaned up automatically when it goes out of scope
        // But we want to keep it alive for the duration of the jail
        std::mem::forget(_table);

        Ok(())
    }

    /// Setup NAT on the host for namespace connectivity
    fn setup_host_nat(&mut self) -> Result<()> {
        // Create NFTable resource
        let mut nftable = ManagedResource::<NFTable>::create(&self.config.jail_id)?;

        // Create and add the host-side nftables table
        if let Some(table_wrapper) = nftable.inner_mut() {
            let table = nftables::NFTable::new_host_table(
                &self.config.jail_id,
                &self.subnet_cidr,
                self.config.http_proxy_port,
                self.config.https_proxy_port,
            )?;
            table_wrapper.set_table(table);

            info!(
                "Set up NAT rules for namespace {} with subnet {}",
                self.namespace_name(),
                self.subnet_cidr
            );
        }

        self.nftables = Some(nftable);
        Ok(())
    }

    /// Start DNS server using /etc/netns/ mechanism
    ///
    /// ## DNS Strategy Overview
    ///
    /// Uses Linux kernel's built-in /etc/netns/ feature:
    ///
    /// 1. **Create /etc/netns/httpjail_<id>/resolv.conf** pointing to host_ip
    ///    - Kernel automatically bind-mounts it when entering namespace
    ///    - All DNS queries from namespace go to host_ip
    ///    - Works with symlinked /etc/resolv.conf
    ///    - Standard Linux mechanism, simple and robust
    ///
    /// 2. **Host DNS server** (runs in this process on host side):
    ///    - Binds to host_ip:53 on the host side of the veth pair
    ///    - Handles all DNS queries from the namespace
    ///    - Returns dummy IP 6.6.6.6 to prevent data exfiltration
    fn start_dns_server(&mut self) -> Result<()> {
        let host_ip_str = format!(
            "{}.{}.{}.{}",
            self.host_ip[0], self.host_ip[1], self.host_ip[2], self.host_ip[3]
        );

        // 1. Create /etc/netns/httpjail_<id>/resolv.conf (kernel auto-mounts it)
        info!(
            "Creating /etc/netns resolv.conf with nameserver {}",
            host_ip_str
        );

        let netns_resolv = NetnsResolv::create_with_nameserver(&self.config.jail_id, &host_ip_str)
            .context("Failed to create /etc/netns resolv.conf")?;

        self.netns_resolv = Some(ManagedResource::from_resource(netns_resolv));

        // 2. Start host DNS server
        info!("Starting host DNS server on {}", host_ip_str);

        let mut host_server = dns::DummyDnsServer::new();
        let host_addr = format!("{}:53", host_ip_str);
        host_server
            .start(&host_addr)
            .context("Failed to start host DNS server")?;

        info!("Started host DNS server on {}", host_addr);
        self.host_dns_server = Some(host_server);

        Ok(())
    }

    /// Stop the DNS server
    fn stop_dns_server(&mut self) {
        // Stop host DNS server (runs in threads, cleanup on drop)
        if let Some(_server) = self.host_dns_server.take() {
            debug!("Stopping host DNS server (cleanup on drop)");
        }
    }
}

impl Drop for LinuxJail {
    fn drop(&mut self) {
        // Stop the DNS server if running
        self.stop_dns_server();
    }
}

impl Jail for LinuxJail {
    fn setup(&mut self, _proxy_port: u16) -> Result<()> {
        // Check for root access
        Self::check_root()?;

        // Create network namespace
        self.create_namespace()?;

        // Set up veth pair
        self.setup_veth_pair()?;

        // Configure host networking FIRST so the veth link is up
        self.configure_host_networking()?;

        // Configure namespace networking after host side is ready
        self.configure_namespace_networking()?;

        // Start the dummy DNS server in the namespace
        self.start_dns_server()?;

        // Set up NAT for namespace connectivity
        self.setup_host_nat()?;

        // Add nftables rules inside namespace
        self.setup_namespace_nftables()?;

        info!(
            "Linux jail setup complete using namespace {} with HTTP proxy on port {} and HTTPS proxy on port {}",
            self.namespace_name(),
            self.config.http_proxy_port,
            self.config.https_proxy_port
        );
        Ok(())
    }

    fn execute(&self, command: &[String], extra_env: &[(String, String)]) -> Result<ExitStatus> {
        if command.is_empty() {
            anyhow::bail!("No command specified");
        }

        debug!(
            "Executing command in namespace {}: {:?}",
            self.namespace_name(),
            command
        );

        // Check if we're running as root and should drop privileges
        let current_uid = unsafe { libc::getuid() };
        let drop_privs = if current_uid == 0 {
            // Running as root - check for SUDO_UID/SUDO_GID to drop privileges to original user
            match (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
                (Ok(uid), Ok(gid)) => {
                    debug!(
                        "Will drop privileges to uid={} gid={} after entering namespace",
                        uid, gid
                    );
                    Some((uid, gid))
                }
                _ => {
                    debug!("Running as root but no SUDO_UID/SUDO_GID found, continuing as root");
                    None
                }
            }
        } else {
            // Not root - no privilege dropping needed
            None
        };

        // CRITICAL: ip netns exec automatically creates a mount namespace and bind-mounts
        // /etc/netns/<namespace>/resolv.conf over /etc/resolv.conf. This is THE STANDARD
        // way to provide custom DNS configuration to network namespaces without touching
        // the host's /etc/resolv.conf.
        //
        // HOWEVER: When /etc/resolv.conf is a symlink (common with systemd-resolved),
        // the symlink target might not exist in the new mount namespace, causing the
        // bind-mount to fail.  We must create the symlink target BEFORE ip netns exec
        // attempts the bind-mount, and we must do it in the SAME ip netns exec invocation
        // (since each invocation gets its own ephemeral mount namespace).
        //
        // Solution: Wrap the user command in a shell that:
        // 1. Creates /run/systemd/resolve/stub-resolv.conf placeholder
        // 2. Execs the user command (with optional setpriv for privilege dropping)
        //
        // Reference: https://man7.org/linux/man-pages/man8/ip-netns.8.html

        // Build the inner command parts
        let mut inner_cmd_parts = Vec::new();

        // Add setpriv if needed
        if let Some((uid, gid)) = drop_privs {
            inner_cmd_parts.push("setpriv".to_string());
            inner_cmd_parts.push(format!("--reuid={}", uid));
            inner_cmd_parts.push(format!("--regid={}", gid));
            inner_cmd_parts.push("--init-groups".to_string());
            inner_cmd_parts.push("--".to_string());
        }

        // Add user command
        for arg in command {
            inner_cmd_parts.push(arg.to_string());
        }

        // Shell-escape each argument
        let escaped_parts: Vec<String> = inner_cmd_parts
            .iter()
            .map(|s| format!("'{}'", s.replace('\'', "'\\''")))
            .collect();

        // Build wrapper shell command that creates placeholder then execs user command
        let shell_cmd = format!(
            "mkdir -p /run/systemd/resolve && touch /run/systemd/resolve/stub-resolv.conf && exec {}",
            escaped_parts.join(" ")
        );

        // Build command: ip netns exec <namespace> sh -c '<wrapper>'
        let mut cmd = Command::new("ip");
        cmd.args([
            "netns",
            "exec",
            &self.namespace_name(),
            "sh",
            "-c",
            &shell_cmd,
        ]);

        // Set environment variables
        for (key, value) in extra_env {
            cmd.env(key, value);
        }

        // Preserve SUDO environment variables for consistency with macOS
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            cmd.env("SUDO_USER", sudo_user);
        }
        if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
            cmd.env("SUDO_UID", sudo_uid);
        }
        if let Ok(sudo_gid) = std::env::var("SUDO_GID") {
            cmd.env("SUDO_GID", sudo_gid);
        }

        debug!("Executing command: {:?}", cmd);

        // Note: We do NOT set HTTP_PROXY/HTTPS_PROXY environment variables here.
        // The jail uses nftables rules to transparently redirect traffic to the proxy,
        // making it work with applications that don't respect proxy environment variables.

        let status = cmd
            .status()
            .context("Failed to execute command in namespace")?;

        Ok(status)
    }

    fn cleanup(&self) -> Result<()> {
        // Since the jail might be in an Arc (e.g., for signal handling),
        // we can't rely on Drop alone. We need to explicitly trigger cleanup
        // of the managed resources by taking them out of the jail.
        // However, since cleanup takes &self not &mut self, we can't modify the jail.
        // The best we can do is ensure the orphan cleanup works.
        info!("Triggering jail cleanup for {}", self.config.jail_id);

        // Call the static cleanup method which will clean up all resources
        Self::cleanup_orphaned(&self.config.jail_id)?;

        Ok(())
    }

    fn jail_id(&self) -> &str {
        &self.config.jail_id
    }

    fn cleanup_orphaned(jail_id: &str) -> Result<()>
    where
        Self: Sized,
    {
        debug!("Cleaning up orphaned Linux jail: {}", jail_id);

        // Create managed resources for existing system resources
        // When these go out of scope, they will clean themselves up
        let _namespace = ManagedResource::<NetworkNamespace>::for_existing(jail_id);
        let _veth = ManagedResource::<VethPair>::for_existing(jail_id);
        let _nftables = ManagedResource::<NFTable>::for_existing(jail_id);
        let _netns_resolv = ManagedResource::<NetnsResolv>::for_existing(jail_id);

        Ok(())
    }
}

impl Clone for LinuxJail {
    fn clone(&self) -> Self {
        // Note: We don't clone the ManagedResource fields as they represent
        // system resources that shouldn't be duplicated
        Self {
            config: self.config.clone(),
            namespace: None,
            veth_pair: None,
            nftables: None,
            netns_resolv: None,
            host_dns_server: None,
            host_ip: self.host_ip,
            host_cidr: self.host_cidr.clone(),
            guest_cidr: self.guest_cidr.clone(),
            subnet_cidr: self.subnet_cidr.clone(),
        }
    }
}
