use super::{Jail, JailConfig};
use crate::sys_resource::ManagedResource;
use anyhow::{Context, Result};
use resources::{MacOSGroup, PfAnchor, PfRulesFile};
use std::fs;
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

mod fork;
mod resources;

pub struct MacOSJail {
    config: JailConfig,
    group: Option<ManagedResource<MacOSGroup>>,
    pf_anchor: Option<ManagedResource<PfAnchor>>,
    pf_rules_file: Option<ManagedResource<PfRulesFile>>,
}

impl MacOSJail {
    pub fn new(config: JailConfig) -> Result<Self> {
        Ok(Self {
            config,
            group: None,
            pf_anchor: None,
            pf_rules_file: None,
        })
    }

    /// Get or create the httpjail group
    fn ensure_group(&mut self) -> Result<u32> {
        // If we already have a group resource, return its GID
        if let Some(ref group) = self.group
            && let Some(g) = group.inner()
            && let Some(gid) = g.gid()
        {
            return Ok(gid);
        }

        // Try to get existing group first
        let group_name = format!("httpjail_{}", self.config.jail_id);
        let output = Command::new("dscl")
            .args([
                ".",
                "-read",
                &format!("/Groups/{}", group_name),
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
                info!("Using existing group {} with GID {}", group_name, gid);
                // Create a ManagedResource for the existing group
                self.group = Some(ManagedResource::for_existing(&self.config.jail_id));
                return Ok(gid);
            }
        }

        // Create new group using ManagedResource
        info!("Creating group {}", group_name);
        let group = ManagedResource::<MacOSGroup>::create(&self.config.jail_id)?;
        let gid = group
            .inner()
            .and_then(|g| g.gid())
            .context("Failed to get GID from created group")?;

        info!("Created group {} with GID {}", group_name, gid);
        self.group = Some(group);
        Ok(gid)
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
    fn load_pf_rules(&mut self, rules: &str) -> Result<()> {
        // Create PF rules file resource if not exists
        if self.pf_rules_file.is_none() {
            self.pf_rules_file = Some(ManagedResource::<PfRulesFile>::create(
                &self.config.jail_id,
            )?);
        }

        // Write rules to file
        let rules_path = self
            .pf_rules_file
            .as_ref()
            .and_then(|f| f.inner())
            .map(|f| f.path().to_string())
            .context("Failed to get rules file path")?;
        fs::write(&rules_path, rules).context("Failed to write PF rules file")?;

        // Create PF anchor resource if not exists
        if self.pf_anchor.is_none() {
            self.pf_anchor = Some(ManagedResource::<PfAnchor>::create(&self.config.jail_id)?);
        }

        let anchor_name = self
            .pf_anchor
            .as_ref()
            .and_then(|a| a.inner())
            .map(|a| a.name().to_string())
            .context("Failed to get anchor name")?;

        // Load rules into our namespaced anchor (under com.apple/httpjail/*)
        info!(
            "Loading PF rules from {} into anchor {}",
            rules_path, anchor_name
        );
        let output = Command::new("pfctl")
            .args(["-a", &anchor_name, "-f", &rules_path])
            .output()
            .context("Failed to load PF rules")?;

        // Check for actual errors vs warnings
        let stderr = String::from_utf8_lossy(&output.stderr);

        // The -f warning is not fatal, but resource busy is
        if stderr.contains("Resource busy") {
            // Try to flush the anchor first and retry
            warn!("PF anchor busy, attempting to flush and retry");
            let _ = Command::new("pfctl")
                .args(["-a", &anchor_name, "-F", "rules"])
                .output();

            // Retry loading rules
            let retry_output = Command::new("pfctl")
                .args(["-a", &anchor_name, "-f", &rules_path])
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

        // We rely on the system default pf.conf which already includes anchors
        // under "com.apple/*" for rdr and filter stages, so no main rules rewrite
        // is necessary. Our anchor path com.apple/httpjail/<id> is covered.

        // Verify that rules were loaded correctly
        info!("Verifying PF rules in anchor {}", anchor_name);
        let output = Command::new("pfctl")
            .args(["-a", &anchor_name, "-s", "rules"])
            .output()
            .context("Failed to verify PF rules")?;

        if output.status.success() {
            let rules_output = String::from_utf8_lossy(&output.stdout);
            if rules_output.is_empty() {
                warn!(
                    "No rules found in anchor {}! Rules may not be active.",
                    anchor_name
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
        let anchor_name = format!("httpjail_{}", self.config.jail_id);
        let _ = Command::new("pfctl")
            .args(["-a", &anchor_name, "-F", "all"])
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
            .group
            .as_ref()
            .and_then(|g| g.inner())
            .and_then(|g| g.gid())
            .context("No group GID set - jail not set up")?;

        let group_name = format!("httpjail_{}", self.config.jail_id);
        debug!(
            "Executing command with jail group {} (GID {}): {:?}",
            group_name, gid, command
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
        if let Some(ref anchor) = self.pf_anchor
            && let Some(a) = anchor.inner()
            && let Ok(output) = Command::new("pfctl")
                .args(["-vvv", "-sr", "-a", a.name()])
                .output()
            && output.status.success()
        {
            let rules_output = String::from_utf8_lossy(&output.stdout);
            info!("PF rules before cleanup:\n{}", rules_output);
        }

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
        info!("Cleaning up orphaned macOS jail: {}", jail_id);

        // Create managed resources for existing system resources
        // When these go out of scope, they will clean themselves up
        let _anchor = ManagedResource::<PfAnchor>::for_existing(jail_id);
        let _group = ManagedResource::<MacOSGroup>::for_existing(jail_id);
        let _rules_file = ManagedResource::<PfRulesFile>::for_existing(jail_id);

        Ok(())
    }
}

impl Clone for MacOSJail {
    fn clone(&self) -> Self {
        // Note: We don't clone the ManagedResource fields as they represent
        // system resources that shouldn't be duplicated
        Self {
            config: self.config.clone(),
            group: None,
            pf_anchor: None,
            pf_rules_file: None,
        }
    }
}
