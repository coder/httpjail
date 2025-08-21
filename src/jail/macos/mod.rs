use super::{Jail, JailConfig};
use anyhow::{Context, Result};
use libc;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

mod fork;

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
            .args([
                ".",
                "-read",
                &format!("/Groups/{}", GROUP_NAME),
                "PrimaryGroupID",
            ])
            .output()
            .context("Failed to check group existence")?;

        if output.status.success() {
            // Parse GID from output
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = stdout.lines().find(|l| l.contains("PrimaryGroupID"))
                && let Some(gid_str) = line.split_whitespace().last()
            {
                let gid = gid_str.parse::<u32>().context("Failed to parse GID")?;
                info!("Using existing group {} with GID {}", GROUP_NAME, gid);
                self.group_gid = Some(gid);
                return Ok(gid);
            }
        }

        // Create group if it doesn't exist
        info!("Creating group {}", GROUP_NAME);
        let output = Command::new("dseditgroup")
            .args(["-o", "create", GROUP_NAME])
            .output()
            .context("Failed to create group")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to create group: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Get the newly created group's GID
        let output = Command::new("dscl")
            .args([
                ".",
                "-read",
                &format!("/Groups/{}", GROUP_NAME),
                "PrimaryGroupID",
            ])
            .output()
            .context("Failed to read group GID")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().find(|l| l.contains("PrimaryGroupID"))
            && let Some(gid_str) = line.split_whitespace().last()
        {
            let gid = gid_str.parse::<u32>().context("Failed to parse GID")?;
            info!("Created group {} with GID {}", GROUP_NAME, gid);
            self.group_gid = Some(gid);
            return Ok(gid);
        }

        anyhow::bail!("Failed to get GID for group {}", GROUP_NAME)
    }

    /// Get the default network interface
    fn get_default_interface() -> Result<String> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .context("Failed to get default route")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("interface:") {
                if let Some(interface) = line.split_whitespace().nth(1) {
                    return Ok(interface.to_string());
                }
            }
        }

        // Fallback to en0 if we can't determine
        warn!("Could not determine default interface, using en0");
        Ok("en0".to_string())
    }

    /// Create PF rules for traffic diversion
    fn create_pf_rules(&self, gid: u32) -> Result<String> {
        // Get the default network interface
        let interface = Self::get_default_interface()?;
        info!("Using network interface: {}", interface);

        // PF rules need to:
        // 1. Redirect traffic from processes with httpjail GID to our proxy
        // 2. Allow the proxy itself to make outbound connections
        // NOTE: Rule order matters - translation (rdr) must come before filtering (pass)
        let rules = format!(
            r#"# httpjail PF rules for GID {} on interface {}
# Translation rules (rdr) - redirect traffic on lo0
rdr pass on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port {}
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port {}

# Filtering rules (pass) - route traffic from httpjail group to lo0
# Using group name '{}' instead of GID for compatibility
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 80 group {} keep state
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 group {} keep state

# Also add rules for the specific interface
pass out on {} route-to (lo0 127.0.0.1) inet proto tcp from any to any port 80 group {} keep state
pass out on {} route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 group {} keep state

# Allow proxy itself to make outbound connections
pass out proto tcp from 127.0.0.1 to any keep state

# Allow all loopback traffic
pass on lo0
"#,
            gid,
            interface,
            self.config.http_proxy_port,
            self.config.https_proxy_port,
            GROUP_NAME,
            GROUP_NAME,
            GROUP_NAME,
            interface,
            GROUP_NAME,
            interface,
            GROUP_NAME
        );

        Ok(rules)
    }

    /// Load PF rules into an anchor
    fn load_pf_rules(&self, rules: &str) -> Result<()> {
        // Write rules to temp file
        fs::write(&self.pf_rules_path, rules).context("Failed to write PF rules file")?;

        // Load rules into anchor
        info!("Loading PF rules from {}", self.pf_rules_path);
        let output = Command::new("pfctl")
            .args(["-a", PF_ANCHOR_NAME, "-f", &self.pf_rules_path])
            .output()
            .context("Failed to load PF rules")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to load PF rules: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Enable PF if not already enabled
        info!("Enabling PF");
        let output = Command::new("pfctl")
            .args(["-E"])
            .output()
            .context("Failed to enable PF")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("already enabled") {
                warn!("Failed to enable PF: {}", stderr);
            }
        }

        // IMPORTANT: Make the anchor active by referencing it in the main ruleset
        // We create a temporary main ruleset that includes our anchor
        let main_rules = format!(
            r#"# Temporary main ruleset to include httpjail anchor
# Include default Apple anchors (in required order)
# 1. Normalization
scrub-anchor "com.apple/*"
# 2. Queueing
dummynet-anchor "com.apple/*"
# 3. Translation (NAT/RDR)
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
rdr-anchor "{}"
# 4. Filtering
anchor "com.apple/*"
anchor "{}"
"#,
            PF_ANCHOR_NAME, PF_ANCHOR_NAME
        );

        // Write and load the main ruleset
        let main_rules_path = format!("/tmp/{}_main.pf", self.config.jail_name);
        fs::write(&main_rules_path, main_rules).context("Failed to write main PF rules")?;

        debug!("Loading main PF ruleset with anchor reference");
        let output = Command::new("pfctl")
            .args(["-f", &main_rules_path])
            .output()
            .context("Failed to load main PF rules")?;

        if !output.status.success() {
            warn!(
                "Failed to load main PF rules: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Clean up temp file
        let _ = fs::remove_file(&main_rules_path);

        // Verify that rules were loaded correctly
        info!("Verifying PF rules in anchor {}", PF_ANCHOR_NAME);
        let output = Command::new("pfctl")
            .args(["-a", PF_ANCHOR_NAME, "-s", "rules"])
            .output()
            .context("Failed to verify PF rules")?;

        if output.status.success() {
            let rules_output = String::from_utf8_lossy(&output.stdout);
            if rules_output.is_empty() {
                warn!(
                    "No rules found in anchor {}! Rules may not be active.",
                    PF_ANCHOR_NAME
                );
            } else {
                debug!("Loaded PF rules:\n{}", rules_output);
                info!(
                    "PF rules loaded successfully - {} rules active",
                    rules_output.lines().filter(|l| !l.is_empty()).count()
                );
            }
        } else {
            warn!(
                "Could not verify PF rules: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Remove PF rules from anchor
    fn unload_pf_rules(&self) -> Result<()> {
        info!("Removing PF rules from anchor {}", PF_ANCHOR_NAME);

        // Flush the anchor
        let output = Command::new("pfctl")
            .args(["-a", PF_ANCHOR_NAME, "-F", "all"])
            .output()
            .context("Failed to flush PF anchor")?;

        if !output.status.success() {
            warn!(
                "Failed to flush PF anchor: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Clean up temp file
        if Path::new(&self.pf_rules_path).exists() {
            fs::remove_file(&self.pf_rules_path).context("Failed to remove PF rules file")?;
        }

        Ok(())
    }
}

impl Jail for MacOSJail {
    fn setup(&mut self, _proxy_port: u16) -> Result<()> {
        // Check if we're running as root
        let uid = unsafe { libc::getuid() };
        if uid != 0 {
            anyhow::bail!("This tool requires root access. Please run with sudo.");
        }

        // Check if PF is available
        let output = Command::new("pfctl")
            .args(["-s", "info"])
            .output()
            .context("Failed to check PF availability")?;

        if !output.status.success() {
            anyhow::bail!("PF (Packet Filter) is not available on this system");
        }

        // Note: _proxy_port parameter is kept for interface compatibility
        // but we use the configured ports from JailConfig

        // Clean up any existing anchor/rules from previous runs
        info!("Cleaning up any existing PF rules from previous runs");
        let _ = Command::new("pfctl")
            .args(["-a", PF_ANCHOR_NAME, "-F", "all"])
            .output(); // Ignore errors - anchor might not exist

        // Ensure group exists and get GID
        let gid = self.ensure_group()?;

        // Create and load PF rules
        let rules = self.create_pf_rules(gid)?;
        self.load_pf_rules(&rules)?;

        info!(
            "Jail setup complete with HTTP proxy on port {} and HTTPS proxy on port {}",
            self.config.http_proxy_port, self.config.https_proxy_port
        );
        Ok(())
    }

    fn execute(&self, command: &[String], extra_env: &[(String, String)]) -> Result<ExitStatus> {
        if command.is_empty() {
            anyhow::bail!("No command specified");
        }

        // Get the GID we need to use
        let gid = self
            .group_gid
            .context("No group GID set - jail not set up")?;

        debug!(
            "Executing command with jail group {} (GID {}): {:?}",
            GROUP_NAME, gid, command
        );

        // If running as root, check if we should drop to original user
        let target_uid = if unsafe { libc::getuid() } == 0 {
            // Running as root - check for SUDO_UID to drop privileges
            std::env::var("SUDO_UID")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
        } else {
            // Not root - keep current UID
            None
        };

        if let Some(uid) = target_uid {
            debug!("Will drop to user UID {} (from SUDO_UID)", uid);
        }

        // Use direct fork/exec to have precise control over UID/GID setting
        unsafe { fork::fork_exec_with_gid(command, gid, target_uid, extra_env) }
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
