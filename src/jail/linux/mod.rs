mod nftables;
mod resources;

use super::{Jail, JailConfig};
use crate::sys_resource::ManagedResource;
use anyhow::{Context, Result};
use resources::{NFTable, NamespaceConfig, NetworkNamespace, VethPair};
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
    namespace_config: Option<ManagedResource<NamespaceConfig>>,
    nftables: Option<ManagedResource<NFTable>>,
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
            namespace_config: None,
            nftables: None,
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
        let (host_ip, _host_cidr, _guest_cidr, _subnet_cidr) = Self::compute_subnet_for_jail(jail_id);
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

        // Ensure DNS is properly configured in the namespace
        // This is a fallback in case the bind mount didn't work
        self.ensure_namespace_dns()?;

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

        // Create namespace-side nftables rules
        let _table = nftables::NFTable::new_namespace_table(
            &namespace_name,
            &host_ip,
            self.config.http_proxy_port,
            self.config.https_proxy_port,
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

    /// Fix DNS resolution in network namespaces
    ///
    /// ## The DNS Problem
    ///
    /// Network namespaces have isolated network stacks, including their own loopback.
    /// When we create a namespace, it gets a copy of /etc/resolv.conf from the host.
    ///
    /// Common issues:
    /// 1. **systemd-resolved**: Points to 127.0.0.53 which doesn't exist in the namespace
    /// 2. **Local DNS**: Any local DNS resolver (127.0.0.1, etc.) won't be accessible
    /// 3. **Corporate DNS**: Internal DNS servers might not be reachable from the namespace
    /// 4. **CI environments**: Often have minimal or no DNS configuration
    ///
    /// ## Why We Can't Route Loopback Traffic to the Host
    ///
    /// You might think: "Just route 127.0.0.0/8 from the namespace to the host!"
    /// This doesn't work due to Linux kernel security:
    ///
    /// 1. **Martian Packet Protection**: The kernel considers packets with 127.x.x.x
    ///    addresses coming from non-loopback interfaces as "martian" (impossible/spoofed)
    /// 2. **Source Address Validation**: Even with rp_filter=0, the kernel won't accept
    ///    127.x.x.x packets from external interfaces
    /// 3. **Built-in Security**: This is hardcoded in the kernel's IP stack for security -
    ///    loopback addresses should NEVER appear on the network
    ///
    /// Even if we tried:
    /// - `ip route add 127.0.0.53/32 via 10.99.X.1` - packets get dropped
    /// - `nftables DNAT` to rewrite 127.0.0.53 -> host IP - happens too late
    /// - Disabling rp_filter - doesn't help with loopback addresses
    ///
    /// ## Our Solution
    ///
    /// Instead of fighting the kernel's security measures, we:
    /// 1. Always create a custom resolv.conf for the namespace
    /// 2. Use public DNS servers (Google's 8.8.8.8 and 8.8.4.4)
    /// 3. These DNS queries go out through our veth pair and work normally
    ///
    /// **IMPORTANT**: `ip netns add` automatically bind-mounts files from
    /// /etc/netns/<namespace-name>/ to /etc/ inside the namespace when the namespace
    /// is created. We MUST create /etc/netns/<namespace-name>/resolv.conf BEFORE
    /// creating the namespace for this to work. This overrides /etc/resolv.conf
    /// ONLY for processes running in the namespace. The host's /etc/resolv.conf
    /// remains completely untouched.
    ///
    /// This is simpler, more reliable, and doesn't compromise security.
    fn fix_systemd_resolved_dns(&mut self) -> Result<()> {
        let namespace_name = self.namespace_name();

        // Always create namespace config resource and custom resolv.conf
        // This ensures DNS works in all environments, not just systemd-resolved
        info!(
            "Setting up DNS for namespace {} with custom resolv.conf",
            namespace_name
        );

        // Ensure /etc/netns directory exists
        let netns_dir = "/etc/netns";
        if !std::path::Path::new(netns_dir).exists() {
            std::fs::create_dir_all(netns_dir).context("Failed to create /etc/netns directory")?;
            debug!("Created /etc/netns directory");
        }

        // Create namespace config resource
        self.namespace_config = Some(ManagedResource::<NamespaceConfig>::create(
            &self.config.jail_id,
        )?);

        // Write custom resolv.conf that will be bind-mounted into the namespace
        // Use Google's public DNS servers which are reliable and always accessible
        let resolv_conf_path = format!("/etc/netns/{}/resolv.conf", namespace_name);
        std::fs::write(
            &resolv_conf_path,
            "# Custom DNS for httpjail namespace\n\
nameserver 8.8.8.8\n\
nameserver 8.8.4.4\n",
        )
        .context("Failed to write namespace-specific resolv.conf")?;

        info!(
            "Created namespace-specific resolv.conf at {} with Google DNS servers",
            resolv_conf_path
        );

        // Verify the file was created
        if !std::path::Path::new(&resolv_conf_path).exists() {
            anyhow::bail!("Failed to create resolv.conf at {}", resolv_conf_path);
        }

        Ok(())
    }

    /// Ensure DNS works in the namespace by copying resolv.conf if needed
    fn ensure_namespace_dns(&self) -> Result<()> {
        let namespace_name = self.namespace_name();

        // Check if DNS is already working by testing /etc/resolv.conf in namespace
        let check_cmd = Command::new("ip")
            .args(["netns", "exec", &namespace_name, "cat", "/etc/resolv.conf"])
            .output();

        let needs_fix = if let Ok(output) = check_cmd {
            if !output.status.success() {
                info!("Cannot read /etc/resolv.conf in namespace, will fix DNS");
                true
            } else {
                let content = String::from_utf8_lossy(&output.stdout);
                // Check if it's pointing to systemd-resolved or is empty
                if content.is_empty() || content.contains("127.0.0.53") {
                    info!("DNS points to systemd-resolved or is empty in namespace, will fix");
                    true
                } else if content.contains("nameserver") {
                    info!("DNS already configured in namespace {}", namespace_name);
                    false
                } else {
                    info!("No nameserver found in namespace resolv.conf, will fix");
                    true
                }
            }
        } else {
            info!("Failed to check DNS in namespace, will attempt fix");
            true
        };

        if !needs_fix {
            return Ok(());
        }

        // DNS not working, try to fix it by copying a working resolv.conf
        info!(
            "Fixing DNS in namespace {} by copying resolv.conf",
            namespace_name
        );

        // Create a temporary resolv.conf with public DNS
        let temp_resolv = format!("/tmp/httpjail_resolv_{}.conf", &namespace_name);
        std::fs::write(
            &temp_resolv,
            "# Temporary DNS for httpjail namespace\n\
             nameserver 8.8.8.8\n\
             nameserver 8.8.4.4\n\
             nameserver 1.1.1.1\n",
        )?;

        // First, try to directly write to /etc/resolv.conf in the namespace using echo
        let write_cmd = Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespace_name,
                "sh",
                "-c",
                "echo -e 'nameserver 8.8.8.8\\nnameserver 8.8.4.4\\nnameserver 1.1.1.1' > /etc/resolv.conf",
            ])
            .output();

        if let Ok(output) = write_cmd {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to write resolv.conf into namespace: {}", stderr);

                // Try another approach - mount bind
                let mount_cmd = Command::new("ip")
                    .args([
                        "netns",
                        "exec",
                        &namespace_name,
                        "mount",
                        "--bind",
                        &temp_resolv,
                        "/etc/resolv.conf",
                    ])
                    .output();

                if let Ok(mount_output) = mount_cmd {
                    if mount_output.status.success() {
                        info!("Successfully bind-mounted resolv.conf in namespace");
                    } else {
                        let mount_stderr = String::from_utf8_lossy(&mount_output.stderr);
                        warn!("Failed to bind mount resolv.conf: {}", mount_stderr);

                        // Last resort - try copying the file content
                        let cp_cmd = Command::new("cp")
                            .args([
                                &temp_resolv,
                                &format!(
                                    "/proc/self/root/etc/netns/{}/resolv.conf",
                                    namespace_name
                                ),
                            ])
                            .output();

                        if let Ok(cp_output) = cp_cmd
                            && cp_output.status.success()
                        {
                            info!("Successfully copied resolv.conf via /proc");
                        }
                    }
                }
            } else {
                info!("Successfully wrote resolv.conf into namespace");
            }
        }

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_resolv);

        Ok(())
    }
}

impl Jail for LinuxJail {
    fn setup(&mut self, _proxy_port: u16) -> Result<()> {
        // Check for root access
        Self::check_root()?;

        // Fix DNS BEFORE creating namespace so bind mount works
        // The /etc/netns/<namespace>/ directory must exist before namespace creation
        self.fix_systemd_resolved_dns()?;

        // Create network namespace
        self.create_namespace()?;

        // Set up veth pair
        self.setup_veth_pair()?;

        // Configure host networking FIRST so the veth link is up
        self.configure_host_networking()?;

        // Configure namespace networking after host side is ready
        self.configure_namespace_networking()?;

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
        let target_user = if current_uid == 0 {
            // Running as root - check for SUDO_USER to drop privileges to original user
            std::env::var("SUDO_USER").ok()
        } else {
            // Not root - no privilege dropping needed
            None
        };

        if let Some(ref user) = target_user {
            debug!(
                "Will drop to user '{}' (from SUDO_USER) after entering namespace",
                user
            );
        }

        // Build command: ip netns exec <namespace> <command>
        // If we need to drop privileges, we wrap with su
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", &self.namespace_name()]);

        // When we have environment variables to pass OR need to drop privileges,
        // use a shell wrapper to ensure proper environment handling
        if target_user.is_some() || !extra_env.is_empty() {
            // Build shell command with explicit environment exports
            let mut shell_command = String::new();

            // Export environment variables explicitly in the shell command
            for (key, value) in extra_env {
                // Escape the value for shell safety
                let escaped_value = value.replace('\'', "'\\''");
                shell_command.push_str(&format!("export {}='{}'; ", key, escaped_value));
            }

            // Add the actual command with proper escaping
            shell_command.push_str(
                &command
                    .iter()
                    .map(|arg| {
                        // Simple escaping: wrap in single quotes and escape existing single quotes
                        if arg.contains('\'') {
                            format!("\"{}\"", arg.replace('"', "\\\""))
                        } else {
                            format!("'{}'", arg)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            );

            if let Some(user) = target_user {
                // Use su to drop privileges to the original user
                cmd.arg("su");
                cmd.arg("-s"); // Specify shell explicitly
                cmd.arg("/bin/sh"); // Use sh for compatibility
                cmd.arg("-p"); // Preserve environment
                cmd.arg(&user); // Username from SUDO_USER
                cmd.arg("-c"); // Execute command
                cmd.arg(shell_command);
            } else {
                // No privilege dropping but need shell for env vars
                cmd.arg("sh");
                cmd.arg("-c");
                cmd.arg(shell_command);
            }
        } else {
            // No privilege dropping and no env vars, execute directly
            cmd.arg(&command[0]);
            for arg in &command[1..] {
                cmd.arg(arg);
            }
        }

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
        let _config = ManagedResource::<NamespaceConfig>::for_existing(jail_id);
        let _nftables = ManagedResource::<NFTable>::for_existing(jail_id);

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
            namespace_config: None,
            nftables: None,
            host_ip: self.host_ip,
            host_cidr: self.host_cidr.clone(),
            guest_cidr: self.guest_cidr.clone(),
            subnet_cidr: self.subnet_cidr.clone(),
        }
    }
}