// libc is needed for getuid() and kill() system calls on Linux
#[cfg(target_os = "linux")]
extern crate libc;

use super::{Jail, JailConfig};
use anyhow::{Context, Result};
use std::process::{Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

/// Linux jail implementation using network namespaces
/// Provides complete network isolation without persistent system state
pub struct LinuxJail {
    config: JailConfig,
    namespace_name: String,
    veth_host: String,
    veth_ns: String,
    namespace_created: bool,
}

impl LinuxJail {
    pub fn new(config: JailConfig) -> Result<Self> {
        // Generate unique names for concurrent safety
        let unique_id = Self::generate_unique_id();

        Ok(Self {
            config,
            namespace_name: format!("httpjail_{}", unique_id),
            veth_host: format!("veth_h_{}", unique_id),
            veth_ns: format!("veth_n_{}", unique_id),
            namespace_created: false,
        })
    }

    /// Generate a unique ID for namespace and interface names
    fn generate_unique_id() -> String {
        let pid = std::process::id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        // Use PID and nanosecond timestamp for uniqueness and sortability
        format!("{}_{}", pid, timestamp)
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

    /// Create the network namespace
    fn create_namespace(&mut self) -> Result<()> {
        // Try to create namespace with retry logic for concurrent safety
        for attempt in 0..3 {
            let output = Command::new("ip")
                .args(["netns", "add", &self.namespace_name])
                .output()
                .context("Failed to execute ip netns add")?;

            if output.status.success() {
                info!("Created network namespace: {}", self.namespace_name);
                self.namespace_created = true;
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("File exists") && attempt < 2 {
                // Namespace name collision, regenerate and retry
                warn!(
                    "Namespace {} already exists, regenerating name",
                    self.namespace_name
                );
                let unique_id = Self::generate_unique_id();
                self.namespace_name = format!("httpjail_{}", unique_id);
                self.veth_host = format!("veth_h_{}", unique_id);
                self.veth_ns = format!("veth_n_{}", unique_id);
                continue;
            }

            anyhow::bail!("Failed to create namespace: {}", stderr);
        }

        anyhow::bail!("Failed to create namespace after 3 attempts")
    }

    /// Set up veth pair for namespace connectivity
    fn setup_veth_pair(&self) -> Result<()> {
        // Create veth pair
        let output = Command::new("ip")
            .args([
                "link",
                "add",
                &self.veth_host,
                "type",
                "veth",
                "peer",
                "name",
                &self.veth_ns,
            ])
            .output()
            .context("Failed to create veth pair")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to create veth pair: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        debug!("Created veth pair: {} <-> {}", self.veth_host, self.veth_ns);

        // Move veth_ns end into the namespace
        let output = Command::new("ip")
            .args(["link", "set", &self.veth_ns, "netns", &self.namespace_name])
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
        // Commands to run inside the namespace
        let commands = vec![
            // Bring up loopback
            vec!["ip", "link", "set", "lo", "up"],
            // Configure veth interface with IP
            vec!["ip", "addr", "add", "169.254.1.2/30", "dev", &self.veth_ns],
            vec!["ip", "link", "set", &self.veth_ns, "up"],
            // Add default route pointing to host
            vec!["ip", "route", "add", "default", "via", "169.254.1.1"],
        ];

        for cmd_args in commands {
            let mut cmd = Command::new("ip");
            cmd.args(["netns", "exec", &self.namespace_name]);
            cmd.args(&cmd_args);

            let output = cmd.output().context(format!(
                "Failed to execute: ip netns exec {} {:?}",
                self.namespace_name, cmd_args
            ))?;

            if !output.status.success() {
                anyhow::bail!(
                    "Failed to configure namespace networking ({}): {}",
                    cmd_args.join(" "),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        debug!(
            "Configured networking inside namespace {}",
            self.namespace_name
        );
        Ok(())
    }

    /// Configure host side of veth pair
    fn configure_host_networking(&self) -> Result<()> {
        // Configure host side of veth
        let commands = vec![
            vec![
                "ip",
                "addr",
                "add",
                "169.254.1.1/30",
                "dev",
                &self.veth_host,
            ],
            vec!["ip", "link", "set", &self.veth_host, "up"],
        ];

        for cmd_args in commands {
            let output = Command::new("ip")
                .args(&cmd_args)
                .output()
                .context(format!("Failed to execute: {:?}", cmd_args))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Ignore "File exists" errors for IP addresses (might be from previous run)
                if !stderr.contains("File exists") {
                    anyhow::bail!(
                        "Failed to configure host networking ({}): {}",
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

        debug!("Configured host side networking for {}", self.veth_host);
        Ok(())
    }

    /// Add iptables rules inside the namespace for traffic redirection
    fn setup_namespace_iptables(&self) -> Result<()> {
        // Convert port numbers to strings to extend their lifetime
        let http_port_str = self.config.http_proxy_port.to_string();
        let https_port_str = self.config.https_proxy_port.to_string();

        let rules = vec![
            // Redirect HTTP traffic to proxy
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
                "REDIRECT",
                "--to-port",
                &http_port_str,
            ],
            // Redirect HTTPS traffic to proxy
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
                "REDIRECT",
                "--to-port",
                &https_port_str,
            ],
            // Allow local traffic (proxy connections)
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-d",
                "127.0.0.0/8",
                "-j",
                "RETURN",
            ],
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
            cmd.args(["netns", "exec", &self.namespace_name]);
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
            self.namespace_name, self.config.http_proxy_port, self.config.https_proxy_port
        );
        Ok(())
    }

    /// Setup NAT on the host for namespace connectivity
    fn setup_host_nat(&self) -> Result<()> {
        // Add MASQUERADE rule for namespace traffic
        let output = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "169.254.1.0/30",
                "-j",
                "MASQUERADE",
            ])
            .output()
            .context("Failed to add MASQUERADE rule")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore if rule already exists
            if !stderr.contains("File exists") {
                warn!("Failed to add MASQUERADE rule: {}", stderr);
            }
        }

        Ok(())
    }

    /// Clean up all resources
    fn cleanup_internal(&self) -> Result<()> {
        let mut errors = Vec::new();

        // Remove namespace (this also removes veth pair)
        if self.namespace_created {
            let output = Command::new("ip")
                .args(["netns", "del", &self.namespace_name])
                .output()
                .context("Failed to execute ip netns del")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("No such file") {
                    errors.push(format!("Failed to delete namespace: {}", stderr));
                }
            } else {
                debug!("Deleted network namespace: {}", self.namespace_name);
            }
        }

        // Try to remove host veth (in case namespace deletion failed)
        let _ = Command::new("ip")
            .args(["link", "del", &self.veth_host])
            .output();

        // Remove MASQUERADE rule
        let _ = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                "169.254.1.0/30",
                "-j",
                "MASQUERADE",
            ])
            .output();

        if !errors.is_empty() {
            warn!("Cleanup completed with errors: {:?}", errors);
        }

        Ok(())
    }

    /// Clean up orphaned namespaces from previous runs
    pub fn cleanup_orphaned_namespaces() {
        let output = match Command::new("ip").args(["netns", "list"]).output() {
            Ok(output) => output,
            Err(e) => {
                debug!("Failed to list namespaces: {}", e);
                return;
            }
        };

        if !output.status.success() {
            return;
        }

        let namespaces = String::from_utf8_lossy(&output.stdout);
        for line in namespaces.lines() {
            // Look for httpjail_<pid>_* pattern
            if let Some(ns_name) = line.split_whitespace().next() {
                if ns_name.starts_with("httpjail_") {
                    // Extract PID from name
                    let parts: Vec<&str> = ns_name.split('_').collect();
                    if parts.len() >= 2 {
                        if let Ok(pid) = parts[1].parse::<u32>() {
                            // Check if process still exists
                            #[cfg(target_os = "linux")]
                            let exists = unsafe { libc::kill(pid as i32, 0) == 0 };
                            #[cfg(not(target_os = "linux"))]
                            let exists = false; // Assume process doesn't exist on non-Linux

                            if !exists {
                                info!("Cleaning up orphaned namespace: {}", ns_name);
                                let _ = Command::new("ip").args(["netns", "del", ns_name]).output();
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Jail for LinuxJail {
    fn setup(&mut self, _proxy_port: u16) -> Result<()> {
        // Check for root access
        Self::check_root()?;

        // Clean up any orphaned namespaces
        Self::cleanup_orphaned_namespaces();

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

        info!(
            "Linux jail setup complete using namespace {} with HTTP proxy on port {} and HTTPS proxy on port {}",
            self.namespace_name, self.config.http_proxy_port, self.config.https_proxy_port
        );
        Ok(())
    }

    fn execute(&self, command: &[String], extra_env: &[(String, String)]) -> Result<ExitStatus> {
        if command.is_empty() {
            anyhow::bail!("No command specified");
        }

        debug!(
            "Executing command in namespace {}: {:?}",
            self.namespace_name, command
        );

        // Build command: ip netns exec <namespace> <command>
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", &self.namespace_name]);

        // Add the actual command
        cmd.arg(&command[0]);
        for arg in &command[1..] {
            cmd.arg(arg);
        }

        // Set environment variables
        for (key, value) in extra_env {
            cmd.env(key, value);
        }

        // Also ensure the proxy addresses are accessible
        cmd.env(
            "http_proxy",
            format!("http://169.254.1.1:{}", self.config.http_proxy_port),
        );
        cmd.env(
            "https_proxy",
            format!("http://169.254.1.1:{}", self.config.https_proxy_port),
        );
        cmd.env(
            "HTTP_PROXY",
            format!("http://169.254.1.1:{}", self.config.http_proxy_port),
        );
        cmd.env(
            "HTTPS_PROXY",
            format!("http://169.254.1.1:{}", self.config.https_proxy_port),
        );

        let status = cmd
            .status()
            .context("Failed to execute command in namespace")?;

        Ok(status)
    }

    fn cleanup(&self) -> Result<()> {
        info!("Cleaning up Linux jail namespace {}", self.namespace_name);
        self.cleanup_internal()
    }
}

impl Drop for LinuxJail {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        if self.namespace_created {
            if let Err(e) = self.cleanup_internal() {
                error!("Failed to cleanup namespace on drop: {}", e);
            }
        }
    }
}

impl Clone for LinuxJail {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            namespace_name: self.namespace_name.clone(),
            veth_host: self.veth_host.clone(),
            veth_ns: self.veth_ns.clone(),
            namespace_created: self.namespace_created,
        }
    }
}
