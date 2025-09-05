use super::{Jail, JailConfig};
use crate::sys_resource::SystemResource;
use anyhow::{Context, Result};
use camino::Utf8Path;
use resources::{MacOSGroup, PfAnchor, PfRulesFile};
use std::fs;
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

mod fork;
mod resources;

pub struct MacOSJail {
    config: JailConfig,
    group_gid: Option<u32>,
    pf_rules_path: String,
    group_name: String,
    pf_anchor_name: String,
}

impl MacOSJail {
    pub fn new(config: JailConfig) -> Result<Self> {
        let group_name = format!("httpjail_{}", config.jail_id);
        let pf_anchor_name = format!("httpjail_{}", config.jail_id);
        let pf_rules_path = format!("/tmp/httpjail_{}.pf", config.jail_id);

        Ok(Self {
            config,
            group_gid: None,
            pf_rules_path,
            group_name,
            pf_anchor_name,
        })
    }

    /// Get or create the httpjail group
    fn ensure_group(&mut self) -> Result<u32> {
        // Check if group already exists
        let output = Command::new("dscl")
            .args([
                ".",
                "-read",
                &format!("/Groups/{}", self.group_name),
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
                info!("Using existing group {} with GID {}", self.group_name, gid);
                self.group_gid = Some(gid);
                return Ok(gid);
            }
        }

        // Create group if it doesn't exist
        info!("Creating group {}", self.group_name);
        let output = Command::new("dseditgroup")
            .args(["-o", "create", &self.group_name])
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
                &format!("/Groups/{}", self.group_name),
                "PrimaryGroupID",
            ])
            .output()
            .context("Failed to read group GID")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = stdout.lines().find(|l| l.contains("PrimaryGroupID"))
            && let Some(gid_str) = line.split_whitespace().last()
        {
            let gid = gid_str.parse::<u32>().context("Failed to parse GID")?;
            info!("Created group {} with GID {}", self.group_name, gid);
            self.group_gid = Some(gid);
            return Ok(gid);
        }

        anyhow::bail!("Failed to get GID for group {}", self.group_name)
    }

    /// Get the default network interface
    fn get_default_interface() -> Result<String> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .context("Failed to get default route")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("interface:")
                && let Some(interface) = line.split_whitespace().nth(1)
            {
                return Ok(interface.to_string());
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
        // 2. NOT affect any other traffic on the system
        // NOTE: On macOS, we need to use route-to to send httpjail group traffic to lo0,
        // then use rdr on lo0 to redirect to proxy ports
        let rules = format!(
            r#"# httpjail PF rules for GID {} on interface {} (jail: {})
# First, redirect traffic arriving on lo0 to our proxy ports
rdr pass on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port {}
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port {}

# Route httpjail group traffic to lo0 where it will be redirected
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 80 group {} keep state
pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 group {} keep state

# Also handle traffic on the specific interface
pass out on {} route-to (lo0 127.0.0.1) inet proto tcp from any to any port 80 group {} keep state
pass out on {} route-to (lo0 127.0.0.1) inet proto tcp from any to any port 443 group {} keep state

# Allow all loopback traffic
pass on lo0 all
"#,
            gid,
            interface,
            self.config.jail_id,
            self.config.http_proxy_port,
            self.config.https_proxy_port,
            gid,
            gid,
            interface,
            gid,
            interface,
            gid
        );

        Ok(rules)
    }

    /// Load PF rules into an anchor
    fn load_pf_rules(&self, rules: &str) -> Result<()> {
        // Write rules to temp file for debugging
        fs::write(&self.pf_rules_path, rules).context("Failed to write PF rules file")?;

        // Try to load rules using file first (standard approach)
        info!(
            "Loading PF rules from {} into anchor {}",
            self.pf_rules_path, self.pf_anchor_name
        );
        let output = Command::new("pfctl")
            .args(["-a", &self.pf_anchor_name, "-f", &self.pf_rules_path])
            .output()
            .context("Failed to load PF rules")?;

        // Check for actual errors vs warnings
        let stderr = String::from_utf8_lossy(&output.stderr);

        // The -f warning is not fatal, but resource busy is
        if stderr.contains("Resource busy") {
            // Try to flush the anchor first and retry
            warn!("PF anchor busy, attempting to flush and retry");
            let _ = Command::new("pfctl")
                .args(["-a", &self.pf_anchor_name, "-F", "rules"])
                .output();

            // Retry loading rules
            let retry_output = Command::new("pfctl")
                .args(["-a", &self.pf_anchor_name, "-f", &self.pf_rules_path])
                .output()
                .context("Failed to load PF rules on retry")?;

            let retry_stderr = String::from_utf8_lossy(&retry_output.stderr);
            if !retry_output.status.success() && !retry_stderr.contains("Use of -f option") {
                anyhow::bail!("Failed to load PF rules after retry: {}", retry_stderr);
            }
        } else if !output.status.success() && !stderr.contains("Use of -f option") {
            anyhow::bail!("Failed to load PF rules: {}", stderr);
        }

        // Log if we got the -f warning but continued
        if stderr.contains("Use of -f option") {
            debug!("PF rules loaded (ignoring -f flag warning in CI)");
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
            self.pf_anchor_name, self.pf_anchor_name
        );

        // Write and load the main ruleset
        let main_rules_path = format!("/tmp/httpjail_{}_main.pf", self.config.jail_id);
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
        info!("Verifying PF rules in anchor {}", self.pf_anchor_name);
        let output = Command::new("pfctl")
            .args(["-a", &self.pf_anchor_name, "-s", "rules"])
            .output()
            .context("Failed to verify PF rules")?;

        if output.status.success() {
            let rules_output = String::from_utf8_lossy(&output.stdout);
            if rules_output.is_empty() {
                warn!(
                    "No rules found in anchor {}! Rules may not be active.",
                    self.pf_anchor_name
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
        info!("Removing PF rules from anchor {}", self.pf_anchor_name);

        // Flush the anchor
        let output = Command::new("pfctl")
            .args(["-a", &self.pf_anchor_name, "-F", "all"])
            .output()
            .context("Failed to flush PF anchor")?;

        if !output.status.success() {
            warn!(
                "Failed to flush PF anchor: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Clean up temp file
        if Utf8Path::new(&self.pf_rules_path).exists() {
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
            .args(["-a", &self.pf_anchor_name, "-F", "all"])
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
            self.group_name, gid, command
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

        // Note: we intentionally do not set the HTTP(S)_PROXY environment variables
        // to make it easier to check that we're _forcing_ use of the proxy and not
        // merely getting lucky with cooperative applications.

        // Use direct fork/exec to have precise control over UID/GID setting
        unsafe { fork::fork_exec_with_gid(command, gid, target_uid, extra_env) }
    }

    fn cleanup(&self) -> Result<()> {
        // Print verbose PF rules before cleanup for debugging
        let output = Command::new("pfctl")
            .args(["-vvv", "-sr", "-a", &self.pf_anchor_name])
            .output()
            .context("Failed to get verbose PF rules")?;

        if output.status.success() {
            let rules_output = String::from_utf8_lossy(&output.stdout);
            info!("PF rules before cleanup:\n{}", rules_output);
        }

        self.unload_pf_rules()?;

        info!("Jail cleanup complete");
        Ok(())
    }

    fn jail_id(&self) -> &str {
        &self.config.jail_id
    }

    fn cleanup_orphaned(jail_id: &str) -> Result<()>
    where
        Self: Sized,
    {
        info!("Cleaning up orphaned macOS jail: {}", jail_id);

        // Create resource handles for existing resources and let Drop handle cleanup
        let _anchor = PfAnchor::for_existing(jail_id);
        let _group = MacOSGroup::for_existing(jail_id);
        let _rules_file = PfRulesFile::for_existing(jail_id);

        Ok(())
    }
}

impl Clone for MacOSJail {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            group_gid: self.group_gid,
            pf_rules_path: self.pf_rules_path.clone(),
            group_name: self.group_name.clone(),
            pf_anchor_name: self.pf_anchor_name.clone(),
        }
    }
}
