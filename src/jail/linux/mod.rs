mod iptables;
mod resources;

use super::{Jail, JailConfig};
use crate::sys_resource::ManagedResource;
use anyhow::{Context, Result};
use resources::{IPTablesRules, NamespaceConfig, NetworkNamespace, VethPair};
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

/// Linux namespace network configuration constants
pub const LINUX_NS_HOST_IP: [u8; 4] = [169, 254, 1, 1];
pub const LINUX_NS_HOST_CIDR: &str = "169.254.1.1/30";
pub const LINUX_NS_GUEST_CIDR: &str = "169.254.1.2/30";
pub const LINUX_NS_SUBNET: &str = "169.254.1.0/30";

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
/// [Application in Namespace] ---> [iptables DNAT] ---> [Proxy on Host:8040/8043]
///            |                                               |
///     (169.254.1.2)                                   (169.254.1.1)
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
/// 3. **Private IP Range**: 169.254.1.0/30 (link-local, won't conflict with real networks)
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
}

impl LinuxJail {
    pub fn new(config: JailConfig) -> Result<Self> {
        Ok(Self {
            config,
            namespace: None,
            veth_pair: None,
            namespace_config: None,
            iptables_rules: None,
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
        let host_ip = format_ip(LINUX_NS_HOST_IP);

        // Commands to run inside the namespace
        let commands = vec![
            // Bring up loopback
            vec!["ip", "link", "set", "lo", "up"],
            // Configure veth interface with IP
            vec!["ip", "addr", "add", LINUX_NS_GUEST_CIDR, "dev", &veth_ns],
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
            vec!["addr", "add", LINUX_NS_HOST_CIDR, "dev", &veth_host],
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
        let http_dest = format!("{}:{}", format_ip(LINUX_NS_HOST_IP), http_port_str);
        let https_dest = format!("{}:{}", format_ip(LINUX_NS_HOST_IP), https_port_str);

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
                    LINUX_NS_SUBNET,
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
                    LINUX_NS_SUBNET,
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
                    LINUX_NS_SUBNET,
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
                "# Custom DNS for httpjail namespace\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n",
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

        let namespace_name = self.namespace_name();

        // Get original UID for privilege dropping
        let original_uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok());

        // Build the command - using ip netns exec to run in namespace
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", &namespace_name]);

        // If we have an original UID, use su to drop privileges
        if let Some(uid) = original_uid {
            debug!("Dropping privileges to UID {} (from SUDO_UID)", uid);
            cmd.arg("su");
            cmd.arg("-");

            // Get username from UID
            let output = Command::new("id")
                .args(["-un", &uid.to_string()])
                .output()
                .context("Failed to get username from UID")?;

            let username = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if username.is_empty() {
                anyhow::bail!("Could not determine username for UID {}", uid);
            }

            cmd.arg(&username);
            cmd.arg("-c");

            // Join the command and its arguments with proper escaping
            let escaped_cmd: Vec<String> = command
                .iter()
                .map(|arg| {
                    if arg.contains(char::is_whitespace) || arg.contains('\'') {
                        format!("'{}'", arg.replace('\'', "'\\''"))
                    } else {
                        arg.clone()
                    }
                })
                .collect();
            cmd.arg(escaped_cmd.join(" "));
        } else {
            // No privilege dropping needed - run command directly
            cmd.args(command);
        }

        // Add any extra environment variables
        for (key, value) in extra_env {
            cmd.env(key, value);
        }

        debug!(
            "Executing command in namespace {}: {:?}",
            namespace_name, command
        );

        // Execute and get status
        let output = cmd
            .output()
            .context("Failed to execute command in namespace")?;

        // We need to check if the command actually ran
        if !output.status.success() {
            // Check if it's a namespace execution failure vs command failure
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Cannot open network namespace")
                || stderr.contains("No such file or directory")
            {
                anyhow::bail!("Network namespace {} not found", namespace_name);
            }
        }

        // Print output (mimicking normal command execution)
        std::io::Write::write_all(&mut std::io::stdout(), &output.stdout)?;
        std::io::Write::write_all(&mut std::io::stderr(), &output.stderr)?;

        Ok(output.status)
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
        }
    }
}
