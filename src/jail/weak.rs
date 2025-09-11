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

        // Set proxy environment variables
        let http_proxy = format!("http://127.0.0.1:{}", self.config.http_proxy_port);
        let https_proxy = format!("http://127.0.0.1:{}", self.config.https_proxy_port);

        cmd.env("HTTP_PROXY", &http_proxy);
        cmd.env("HTTPS_PROXY", &https_proxy);
        cmd.env("http_proxy", &http_proxy);
        cmd.env("https_proxy", &https_proxy);

        // Also set NO_PROXY for localhost to avoid proxying local connections
        // Preserve any existing NO_PROXY settings by appending them
        let mut no_proxy_hosts = "localhost,127.0.0.1,::1".to_string();

        if let Ok(existing) = std::env::var("NO_PROXY").or_else(|_| std::env::var("no_proxy"))
            && !existing.is_empty()
        {
            no_proxy_hosts = format!("{},{}", existing, no_proxy_hosts);
        }

        cmd.env("NO_PROXY", &no_proxy_hosts);
        cmd.env("no_proxy", &no_proxy_hosts);

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
