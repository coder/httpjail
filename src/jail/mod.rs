use anyhow::Result;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod managed;

// Counter to ensure unique jail IDs even when created rapidly
static JAIL_ID_COUNTER: AtomicU32 = AtomicU32::new(0);

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

    /// Get the unique jail ID for this instance
    fn jail_id(&self) -> &str;

    /// Cleanup orphaned resources for a given jail_id (static dispatch)
    /// This is called when detecting stale canaries from other processes
    fn cleanup_orphaned(jail_id: &str) -> Result<()>
    where
        Self: Sized;
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

    /// Unique identifier for this jail instance
    pub jail_id: String,

    /// Whether to enable heartbeat monitoring
    pub enable_heartbeat: bool,

    /// Interval in seconds between heartbeat touches
    pub heartbeat_interval_secs: u64,

    /// Timeout in seconds before considering a jail orphaned
    pub orphan_timeout_secs: u64,
}

impl JailConfig {
    /// Create a new configuration with a unique jail_id
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();

        // Add counter to ensure uniqueness even when created rapidly
        let counter = JAIL_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

        Self {
            http_proxy_port: 8040,
            https_proxy_port: 8043,
            tls_intercept: true,
            jail_id: format!("{:06}_{:03}", (timestamp % 1_000_000), counter % 1000),
            enable_heartbeat: true,
            heartbeat_interval_secs: 1,
            orphan_timeout_secs: 10,
        }
    }
}

impl Default for JailConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

mod weak;

/// Create a platform-specific jail implementation wrapped with lifecycle management
pub fn create_jail(config: JailConfig, weak_mode: bool) -> Result<Box<dyn Jail>> {
    use self::managed::ManagedJail;

    // Use weak jail if requested (works on all platforms)
    if weak_mode {
        use self::weak::WeakJail;
        return Ok(Box::new(ManagedJail::new(
            WeakJail::new(config.clone())?,
            &config,
        )?));
    }

    // Otherwise use platform-specific implementation
    #[cfg(target_os = "macos")]
    {
        use self::macos::MacOSJail;
        Ok(Box::new(ManagedJail::new(
            MacOSJail::new(config.clone())?,
            &config,
        )?))
    }

    #[cfg(target_os = "linux")]
    {
        use self::linux::LinuxJail;
        Ok(Box::new(ManagedJail::new(
            LinuxJail::new(config.clone())?,
            &config,
        )?))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("Unsupported platform")
    }
}
