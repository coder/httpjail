use anyhow::Result;
use rand::Rng;

pub mod weak;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod managed;

/// Trait for platform-specific jail implementations
#[allow(dead_code)]
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

/// Get the canary directory for tracking jail lifetimes
pub fn get_canary_dir() -> std::path::PathBuf {
    // Use user data directory instead of /tmp to avoid issues with tmp cleaners
    // This ensures canaries persist across reboots and are only removed when we want them to be
    if let Some(data_dir) = dirs::data_dir() {
        data_dir.join("httpjail").join("canaries")
    } else {
        // Fallback to /tmp if we can't get user data dir (should rarely happen)
        std::path::PathBuf::from("/tmp/httpjail")
    }
}

/// Get the directory for httpjail temporary files (like resolv.conf)
pub fn get_temp_dir() -> std::path::PathBuf {
    std::path::PathBuf::from("/tmp/httpjail")
}

/// Jail configuration
#[derive(Clone, Debug)]
pub struct JailConfig {
    /// Port where the HTTP proxy is listening
    pub http_proxy_port: u16,

    /// Port for HTTPS proxy
    pub https_proxy_port: u16,

    /// Port for DNS proxy (transparent redirect)
    pub dns_proxy_port: u16,

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
        // Generate a random 8-character base36 ID (a-z0-9)
        // This gives us 36^8 = ~2.8 trillion possible IDs (~41 bits of entropy)
        let jail_id = Self::generate_base36_id(8);

        Self {
            http_proxy_port: 8040,
            https_proxy_port: 8043,
            dns_proxy_port: 8053,
            jail_id,
            enable_heartbeat: true,
            heartbeat_interval_secs: 1,
            orphan_timeout_secs: 10,
        }
    }

    /// Generate a random base36 ID of the specified length
    fn generate_base36_id(length: usize) -> String {
        const CHARSET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let mut rng = rand::thread_rng();

        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}

impl Default for JailConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a platform-specific jail implementation wrapped with lifecycle management
pub fn create_jail(
    config: JailConfig,
    weak_mode: bool,
    docker_mode: bool,
) -> Result<Box<dyn Jail>> {
    use self::weak::WeakJail;

    // Always use weak jail on macOS due to PF limitations
    // (PF translation rules cannot match on user/group)
    #[cfg(target_os = "macos")]
    {
        let _ = weak_mode; // Suppress unused warning on macOS
        let _ = docker_mode; // Docker mode not supported on macOS
        // WeakJail doesn't need lifecycle management since it creates no system resources
        Ok(Box::new(WeakJail::new(config)?))
    }

    #[cfg(target_os = "linux")]
    {
        use self::linux::LinuxJail;
        use self::linux::docker::DockerLinux;

        if weak_mode {
            // WeakJail doesn't need lifecycle management since it creates no system resources
            Ok(Box::new(WeakJail::new(config)?))
        } else if docker_mode {
            // DockerLinux wraps LinuxJail with Docker-specific execution
            Ok(Box::new(self::managed::ManagedJail::new(
                DockerLinux::new(config.clone())?,
                &config,
            )?))
        } else {
            // LinuxJail creates system resources (namespaces, iptables) that need cleanup
            Ok(Box::new(self::managed::ManagedJail::new(
                LinuxJail::new(config.clone())?,
                &config,
            )?))
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("Unsupported platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base36_jail_id_generation() {
        // Generate multiple IDs and verify they are valid base36
        for _ in 0..100 {
            let config = JailConfig::new();
            let id = &config.jail_id;

            // Check length
            assert_eq!(id.len(), 8, "ID should be 8 characters long");

            // Check all characters are base36 (0-9, a-z)
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "ID should only contain lowercase letters and digits: {}",
                id
            );
        }
    }

    #[test]
    fn test_jail_id_uniqueness() {
        // Generate many IDs and check for collisions
        use std::collections::HashSet;
        let mut ids = HashSet::new();

        for _ in 0..1000 {
            let config = JailConfig::new();
            let id = config.jail_id.clone();

            // Check that this ID hasn't been seen before
            assert!(ids.insert(id.clone()), "Duplicate ID generated: {}", id);
        }

        // We generated 1000 unique IDs
        assert_eq!(ids.len(), 1000);
    }
}
