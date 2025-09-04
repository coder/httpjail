use anyhow::Result;

/// Trait for platform-specific jail implementations
pub trait Jail: Send + Sync {
    /// Setup jail for a specific session
    fn setup(&mut self, proxy_port: u16) -> Result<()>;

    /// Execute a command within the jail with additional environment variables.
    ///
    /// # Important
    ///
    /// System-native jail implementations (macOS/Linux) do NOT set HTTP_PROXY/HTTPS_PROXY
    /// environment variables. Instead, they use platform-specific mechanisms to transparently
    /// redirect traffic:
    /// - macOS: Uses PF (Packet Filter) rules to redirect traffic from the httpjail group
    /// - Linux: Uses iptables rules in a network namespace to redirect traffic
    ///
    /// The WeakJail implementation does set HTTP_PROXY/HTTPS_PROXY environment variables
    /// since it relies on applications respecting these variables.
    ///
    /// This approach ensures that system-native jails capture all network traffic,
    /// even from applications that don't respect proxy environment variables.
    fn execute(
        &self,
        command: &[String],
        extra_env: &[(String, String)],
    ) -> Result<std::process::ExitStatus>;

    /// Cleanup jail resources
    fn cleanup(&self) -> Result<()>;
}

/// Configuration for jail setup
#[derive(Debug, Clone)]
pub struct JailConfig {
    /// Port where the HTTP proxy is listening
    pub http_proxy_port: u16,

    /// Port for HTTPS proxy
    pub https_proxy_port: u16,

    /// Whether to use TLS interception
    #[allow(dead_code)]
    pub tls_intercept: bool,

    /// Name/identifier for this jail instance
    #[allow(dead_code)]
    pub jail_name: String,
}

impl Default for JailConfig {
    fn default() -> Self {
        Self {
            // Use ports 8040 and 8043 - clearly HTTP-related
            // Similar to common proxy ports (8080, 8443) but less likely to conflict
            http_proxy_port: 8040,
            https_proxy_port: 8043,
            tls_intercept: true,
            jail_name: "httpjail".to_string(),
        }
    }
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

mod weak;

/// Create a platform-specific jail implementation
pub fn create_jail(config: JailConfig, weak_mode: bool) -> Result<Box<dyn Jail>> {
    // Use weak jail if requested (works on all platforms)
    if weak_mode {
        use self::weak::WeakJail;
        return Ok(Box::new(WeakJail::new(config)?));
    }

    // Otherwise use platform-specific implementation
    #[cfg(target_os = "macos")]
    {
        use self::macos::MacOSJail;
        Ok(Box::new(MacOSJail::new(config)?))
    }

    #[cfg(target_os = "linux")]
    {
        use self::linux::LinuxJail;
        Ok(Box::new(LinuxJail::new(config)?))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("Unsupported platform")
    }
}
