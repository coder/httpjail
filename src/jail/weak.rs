use super::{Jail, JailConfig};
use anyhow::Result;
use std::process::{Command, ExitStatus};
use tracing::{debug, info};

/// Weak jail implementation that uses environment variables only
/// No system-level packet filtering, no sudo required
pub struct WeakJail {
    config: JailConfig,
}

impl WeakJail {
    pub fn new(config: JailConfig) -> Result<Self> {
        Ok(Self { config })
    }
}

impl Jail for WeakJail {
    fn setup(&mut self, _proxy_port: u16) -> Result<()> {
        info!("Setting up weak jail (environment variables only)");
        info!(
            "HTTP proxy will be set to: http://127.0.0.1:{}",
            self.config.http_proxy_port
        );
        info!(
            "HTTPS proxy will be set to: http://127.0.0.1:{}",
            self.config.https_proxy_port
        );

        Ok(())
    }

    fn execute(&self, command: &[String], extra_env: &[(String, String)]) -> Result<ExitStatus> {
        if command.is_empty() {
            anyhow::bail!("No command specified");
        }

        debug!(
            "Executing command with proxy environment variables: {:?}",
            command
        );

        // Execute the command with proxy environment variables
        let mut cmd = Command::new(&command[0]);
        for arg in &command[1..] {
            cmd.arg(arg);
        }

        // The parent's proxy variables configure httpjail's own egress. None of
        // them may survive into the jailed process, so clear them all before
        // setting the ones that point at httpjail.
        super::remove_parent_proxy_env(&mut cmd);

        // Set proxy environment variables
        let http_proxy = format!("http://127.0.0.1:{}", self.config.http_proxy_port);
        let https_proxy = format!("http://127.0.0.1:{}", self.config.https_proxy_port);

        cmd.env("HTTP_PROXY", &http_proxy);
        cmd.env("HTTPS_PROXY", &https_proxy);
        cmd.env("http_proxy", &http_proxy);
        cmd.env("https_proxy", &https_proxy);

        // Keep local connections off the proxy, which would otherwise loop back
        // through httpjail. The parent's NO_PROXY is deliberately not merged in:
        // any entry it names would let the jailed process reach that destination
        // directly, with no rule evaluation at all.
        //
        // Both spellings are set because tools disagree on which they read.
        let no_proxy_hosts = "localhost,127.0.0.1,::1";
        cmd.env("NO_PROXY", no_proxy_hosts);
        cmd.env("no_proxy", no_proxy_hosts);

        // Set any extra environment variables
        for (key, value) in extra_env {
            cmd.env(key, value);
        }

        info!(
            "Running command with HTTP_PROXY={} HTTPS_PROXY={}",
            http_proxy, https_proxy
        );

        let status = cmd
            .status()
            .map_err(|e| anyhow::anyhow!("Failed to execute command: {}", e))?;

        Ok(status)
    }

    fn cleanup(&self) -> Result<()> {
        debug!("Weak jail cleanup");
        Ok(())
    }

    fn jail_id(&self) -> &str {
        &self.config.jail_id
    }

    fn cleanup_orphaned(_jail_id: &str) -> Result<()>
    where
        Self: Sized,
    {
        // Weak jail doesn't create any system resources, so nothing to clean
        Ok(())
    }
}
