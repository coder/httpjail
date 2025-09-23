use super::JailConfig;

impl JailConfig {
    /// Create a configuration optimized for CI environments
    /// Uses more aggressive cleanup timeouts to prevent resource accumulation
    pub fn for_ci() -> Self {
        let mut config = Self::new();
        
        // Use 2 second orphan timeout in CI instead of 10 seconds
        // This ensures orphans are cleaned up quickly between test runs
        config.orphan_timeout_secs = 2;
        
        // More frequent heartbeat to detect crashes faster
        config.heartbeat_interval_secs = 1;
        
        config
    }
    
    /// Check if we're running in CI environment
    pub fn is_ci() -> bool {
        std::env::var("CI").is_ok() || 
        std::env::var("GITHUB_ACTIONS").is_ok() ||
        // Check if we're on the ci-1 host
        std::fs::read_to_string("/etc/hostname")
            .map(|h| h.trim() == "ci-1")
            .unwrap_or(false)
    }
}