use super::{Jail, JailConfig};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

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
        let output = Command::new("sudo")
            .args(["dseditgroup", "-o", "create", GROUP_NAME])
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

    /// Create PF rules for traffic diversion
    fn create_pf_rules(&self, _gid: u32) -> Result<String> {
        // Note: macOS PF uses group name, not GID
        let rules = format!(
            r#"# httpjail PF rules
# First, redirect HTTP and HTTPS traffic to local proxy ports
rdr pass on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port {}
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port {}

# Route outgoing HTTP/HTTPS traffic from httpjail group to lo0 for redirection
pass out route-to lo0 inet proto tcp from any to any port 80 group {} keep state
pass out route-to lo0 inet proto tcp from any to any port 443 group {} keep state

# Allow proxy to make outbound connections
pass out proto tcp from 127.0.0.1 to any keep state

# Allow all loopback traffic
pass on lo0
"#,
            self.config.http_proxy_port, self.config.https_proxy_port, GROUP_NAME, GROUP_NAME
        );

        Ok(rules)
    }

    /// Load PF rules into an anchor
    fn load_pf_rules(&self, rules: &str) -> Result<()> {
        // Write rules to temp file
        fs::write(&self.pf_rules_path, rules).context("Failed to write PF rules file")?;

        // Load rules into anchor
        info!("Loading PF rules from {}", self.pf_rules_path);
        let output = Command::new("sudo")
            .args(["pfctl", "-a", PF_ANCHOR_NAME, "-f", &self.pf_rules_path])
            .output()
            .context("Failed to load PF rules")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to load PF rules: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Enable PF if not already enabled
        let _ = Command::new("sudo").args(["pfctl", "-E"]).output();

        info!("PF rules loaded successfully");
        Ok(())
    }

    /// Remove PF rules from anchor
    fn unload_pf_rules(&self) -> Result<()> {
        info!("Removing PF rules from anchor {}", PF_ANCHOR_NAME);

        // Flush the anchor
        let output = Command::new("sudo")
            .args(["pfctl", "-a", PF_ANCHOR_NAME, "-F", "all"])
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
        // Check if we have sudo access
        let output = Command::new("sudo")
            .args(["-n", "true"])
            .output()
            .context("Failed to check sudo access")?;

        if !output.status.success() {
            anyhow::bail!(
                "This tool requires sudo access. Please run with sudo or authenticate first."
            );
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

        debug!(
            "Executing command with jail group {}: {:?}",
            GROUP_NAME, command
        );

        // Execute the command directly - PF rules will intercept based on the process
        let mut cmd = Command::new(&command[0]);
        for arg in &command[1..] {
            cmd.arg(arg);
        }

        // Set the HTTP_PROXY and HTTPS_PROXY environment variables
        // This is needed for curl and other tools to use our proxy
        cmd.env(
            "HTTP_PROXY",
            format!("http://127.0.0.1:{}", self.config.http_proxy_port),
        );
        cmd.env(
            "HTTPS_PROXY",
            format!("http://127.0.0.1:{}", self.config.https_proxy_port),
        );
        cmd.env(
            "http_proxy",
            format!("http://127.0.0.1:{}", self.config.http_proxy_port),
        );
        cmd.env(
            "https_proxy",
            format!("http://127.0.0.1:{}", self.config.https_proxy_port),
        );

        // Set any extra environment variables (e.g., CA cert paths)
        for (key, value) in extra_env {
            cmd.env(key, value);
        }

        let status = cmd
            .status()
            .context("Failed to execute command with jail")?;

        Ok(status)
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
