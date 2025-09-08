mod iptables;
mod resources;

use super::{Jail, JailConfig};
use crate::sys_resource::ManagedResource;
use anyhow::{Context, Result};
use resources::{IPTablesRules, NamespaceConfig, NetworkNamespace, VethPair};
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
/// [Application in Namespace] ---> [iptables/ip6tables DNAT] ---> [Proxy on Host:HTTP/HTTPS]
///            |                                               |
///     (169.254.X.2)                                   (169.254.X.1)
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
/// 3. **Private IP Range**: Unique per-jail /30 within 169.254.0.0/16 (link-local)
/// 4. **iptables DNAT**: Transparent redirection without environment variables
/// 5. **DNS Override**: Handle systemd-resolved incompatibility with namespaces
///
/// ## Cleanup Guarantees
///
/// Resources are cleaned up in priority order:
/// 1. **Namespace deletion**: Automatically cleans up veth pair and namespace iptables rules
/// 2. **Host iptables rules**: Tagged with comments for identification and cleanup
/// 3. **Config directory**: /etc/netns/<namespace>/ removed if it exists
///
/// The namespace deletion is the critical cleanup - even if host iptables cleanup fails,
/// the jail is effectively destroyed once the namespace is gone.
///
/// Provides complete network isolation without persistent system state
pub struct LinuxJail {
    config: JailConfig,
    namespace: Option<ManagedResource<NetworkNamespace>>,
    veth_pair: Option<ManagedResource<VethPair>>,
    namespace_config: Option<ManagedResource<NamespaceConfig>>,
    iptables_rules: Option<ManagedResource<IPTablesRules>>,
    // Per-jail computed networking (unique /30 inside 169.254/16)
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
            iptables_rules: None,
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

    /// Compute a stable unique /30 in 169.254.0.0/16 for this jail
    /// There are 16384 possible /30 subnets in the /16.
    fn compute_subnet_for_jail(jail_id: &str) -> ([u8; 4], String, String, String) {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        jail_id.hash(&mut hasher);
        let h = hasher.finish();
        let idx = (h % 16384) as u32; // 0..16383
        let base = idx * 4; // network base offset within 169.254/16
        let third = ((base >> 8) & 0xFF) as u8;
        let fourth = (base & 0xFF) as u8;
        let network = [169u8, 254u8, third, fourth];
        let host_ip = [network[0], network[1], network[2], network[3].saturating_add(1)];
        let guest_ip = [network[0], network[1], network[2], network[3].saturating_add(2)];
        let host_cidr = format!("{}/30", format_ip(host_ip));
        let guest_cidr = format!("{}/30", format_ip(guest_ip));
        let subnet_cidr = format!("{}/30", format_ip(network));
        (host_ip, host_cidr, guest_cidr, subnet_cidr)
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

            let output = cmd.output().context(format!(
                "Failed to execute: ip netns exec {} {:?}",
                namespace_name, cmd_args
            ))?;

            if !output.status.success() {
                anyhow::bail!(
                    "Failed to configure namespace networking ({}): {}",
                    cmd_args.join(" "),
                    String::from_utf8_lossy(&output.stderr)
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

    /// Add iptables rules inside the namespace for traffic redirection
    ///
    /// We use DNAT (Destination NAT) instead of REDIRECT for a critical reason:
    /// - REDIRECT changes the destination to 127.0.0.1 (localhost) within the namespace
    /// - Our proxy runs on the HOST, not inside the namespace
    /// - DNAT allows us to redirect to the host's IP address (169.254.1.1) where the proxy is actually listening
    /// - This is why we must use DNAT --to-destination 169.254.1.1:8040 instead of REDIRECT --to-port 8040
    fn setup_namespace_iptables(&self) -> Result<()> {
        let namespace_name = self.namespace_name();

        // Convert port numbers to strings to extend their lifetime
        let http_port_str = self.config.http_proxy_port.to_string();
        let https_port_str = self.config.https_proxy_port.to_string();

        // Format destination addresses for DNAT
        // The proxy is listening on the host side of the veth pair (169.254.1.1)
        // We need to redirect traffic to this specific IP:port combination
        let http_dest = format!("{}:{}", format_ip(self.host_ip), http_port_str);
        let https_dest = format!("{}:{}", format_ip(self.host_ip), https_port_str);

        let rules = vec![
            // Skip DNS traffic (port 53) - don't redirect it
            // DNS queries need to reach actual DNS servers (8.8.8.8 or system DNS)
            // If we redirect DNS to our HTTP proxy, resolution will fail
            // RETURN means "stop processing this chain and accept the packet as-is"
            vec![
                "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j",
                "RETURN",
            ],
            vec![
                "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j",
                "RETURN",
            ],
            // Redirect HTTP traffic to proxy on host
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "DNAT",
                "--to-destination",
                &http_dest,
            ],
            // Redirect HTTPS traffic to proxy on host
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "443",
                "-j",
                "DNAT",
                "--to-destination",
                &https_dest,
            ],
            // Allow local network traffic
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-d",
                "169.254.0.0/16",
                "-j",
                "RETURN",
            ],
        ];


        for rule_args in rules {
            let mut cmd = Command::new("ip");
            cmd.args(["netns", "exec", &namespace_name]);
            cmd.args(&rule_args);

            let output = cmd
                .output()
                .context(format!("Failed to execute iptables rule: {:?}", rule_args))?;

            if !output.status.success() {
                anyhow::bail!(
                    "Failed to add iptables rule: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        info!(
            "Set up iptables rules in namespace {} for HTTP:{} HTTPS:{}",
            namespace_name, self.config.http_proxy_port, self.config.https_proxy_port
        );
        Ok(())
    }

    /// Setup NAT on the host for namespace connectivity
    fn setup_host_nat(&mut self) -> Result<()> {
        use iptables::IPTablesRule;

        // Create IPTablesRules resource
        let mut iptables = ManagedResource::<IPTablesRules>::create(&self.config.jail_id)?;

        // Add MASQUERADE rule for namespace traffic with a comment for identification
        // The comment allows us to find and remove this specific rule during cleanup
        let comment = format!("httpjail-{}", self.namespace_name());

        // Create and add rules to the resource
        if let Some(rules) = iptables.inner_mut() {
            // Create MASQUERADE rule
            let masq_rule = IPTablesRule::new(
                Some("nat"),
                "POSTROUTING",
                vec![
                    "-s",
                    &self.subnet_cidr,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "MASQUERADE",
                ],
            )
            .context("Failed to add MASQUERADE rule")?;

            rules.add_rule(masq_rule);

            // Add explicit ACCEPT rules for namespace traffic in FORWARD chain
            //
            // The FORWARD chain controls packets being routed THROUGH this host (not TO/FROM it).
            // Since we're routing packets between the namespace and the internet, they go through FORWARD.
            //
            // Without these rules:
            // - Default FORWARD policy might be DROP/REJECT
            // - Other firewall rules might block our namespace subnet
            // - Docker/Kubernetes/other container tools might have restrictive FORWARD rules
            //
            // We use -I (insert) at position 1 to ensure our rules take precedence.
            // We add comments to make these rules identifiable for cleanup.

            // Forward rule for source traffic
            let forward_src_rule = IPTablesRule::new(
                None, // filter table is default
                "FORWARD",
                vec![
                    "-s",
                    &self.subnet_cidr,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "ACCEPT",
                ],
            )
            .context("Failed to add FORWARD source rule")?;

            rules.add_rule(forward_src_rule);

            // Forward rule for destination traffic
            let forward_dst_rule = IPTablesRule::new(
                None, // filter table is default
                "FORWARD",
                vec![
                    "-d",
                    &self.subnet_cidr,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "ACCEPT",
                ],
            )
            .context("Failed to add FORWARD destination rule")?;

            rules.add_rule(forward_dst_rule);
        }

        self.iptables_rules = Some(iptables);
        Ok(())
    }

    /// Fix DNS if systemd-resolved is in use
    ///
    /// ## The systemd-resolved Problem
    ///
    /// Modern Linux systems often use systemd-resolved as a local DNS stub resolver.
    /// This service listens on 127.0.0.53:53 and /etc/resolv.conf points to it.
    ///
    /// When we create a network namespace:
    /// 1. The namespace gets a COPY of /etc/resolv.conf pointing to 127.0.0.53
    /// 2. But 127.0.0.53 in the namespace is NOT the host's systemd-resolved
    /// 3. Each namespace has its own isolated loopback interface
    /// 4. Result: DNS queries fail because there's no DNS server at 127.0.0.53 in the namespace
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
    /// - `ip route add 127.0.0.53/32 via 169.254.1.1` - packets get dropped
    /// - `iptables DNAT` to rewrite 127.0.0.53 -> host IP - happens too late
    /// - Disabling rp_filter - doesn't help with loopback addresses
    ///
    /// ## Our Solution
    ///
    /// Instead of fighting the kernel's security measures, we:
    /// 1. Detect if /etc/resolv.conf points to systemd-resolved (127.0.0.53)
    /// 2. Replace it with public DNS servers (Google's 8.8.8.8 and 8.8.4.4)
    /// 3. These DNS queries go out through our veth pair and work normally
    ///
    /// **IMPORTANT**: `ip netns exec` automatically bind-mounts files from
    /// /etc/netns/<namespace-name>/ to /etc/ inside the namespace. We create
    /// /etc/netns/<namespace-name>/resolv.conf with our custom DNS servers,
    /// which will override /etc/resolv.conf ONLY for processes running in the namespace.
    /// The host's /etc/resolv.conf remains completely untouched.
    ///
    /// This is simpler, more reliable, and doesn't compromise security.
    fn fix_systemd_resolved_dns(&mut self) -> Result<()> {
        let namespace_name = self.namespace_name();

        // Check if resolv.conf points to systemd-resolved
        let output = Command::new("ip")
            .args([
                "netns",
                "exec",
                &namespace_name,
                "grep",
                "127.0.0.53",
                "/etc/resolv.conf",
            ])
            .output()?;

        if output.status.success() {
            // systemd-resolved is in use, create namespace-specific resolv.conf
            debug!("Detected systemd-resolved, creating namespace-specific resolv.conf");

            // Create namespace config resource
            self.namespace_config = Some(ManagedResource::<NamespaceConfig>::create(
                &self.config.jail_id,
            )?);

            // Write custom resolv.conf that will be bind-mounted into the namespace
            let resolv_conf_path = format!("/etc/netns/{}/resolv.conf", namespace_name);
            std::fs::write(
                &resolv_conf_path,
                "# Custom DNS for httpjail namespace\n\
nameserver 8.8.8.8\n\
nameserver 8.8.4.4\n",
            )
            .context("Failed to write namespace-specific resolv.conf")?;

            debug!(
                "Created namespace-specific resolv.conf at {}",
                resolv_conf_path
            );
        }

        Ok(())
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

        // Configure namespace networking
        self.configure_namespace_networking()?;

        // Configure host networking
        self.configure_host_networking()?;

        // Set up NAT for namespace connectivity
        self.setup_host_nat()?;

        // Add iptables rules inside namespace
        self.setup_namespace_iptables()?;

        // Fix DNS if using systemd-resolved
        self.fix_systemd_resolved_dns()?;

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
        // The jail uses iptables rules to transparently redirect traffic to the proxy,
        // making it work with applications that don't respect proxy environment variables.

        let status = cmd
            .status()
            .context("Failed to execute command in namespace")?;

        Ok(status)
    }

    fn cleanup(&self) -> Result<()> {
        // Resources will be cleaned up automatically when dropped
        // But we can log that cleanup is happening
        info!("Jail cleanup complete - resources will be cleaned up automatically");
        Ok(())
    }

    fn jail_id(&self) -> &str {
        &self.config.jail_id
    }

    fn cleanup_orphaned(jail_id: &str) -> Result<()>
    where
        Self: Sized,
    {
        info!("Cleaning up orphaned Linux jail: {}", jail_id);

        // Create managed resources for existing system resources
        // When these go out of scope, they will clean themselves up
        let _namespace = ManagedResource::<NetworkNamespace>::for_existing(jail_id);
        let _veth = ManagedResource::<VethPair>::for_existing(jail_id);
        let _config = ManagedResource::<NamespaceConfig>::for_existing(jail_id);
        let _iptables = ManagedResource::<IPTablesRules>::for_existing(jail_id);

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
            iptables_rules: None,
            host_ip: self.host_ip,
            host_cidr: self.host_cidr.clone(),
            guest_cidr: self.guest_cidr.clone(),
            subnet_cidr: self.subnet_cidr.clone(),
        }
    }
}
