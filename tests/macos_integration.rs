mod common;
mod system_integration;

#[cfg(target_os = "macos")]
mod tests {
    use super::*;
    use serial_test::serial;

    /// macOS-specific platform implementation
    struct MacOSPlatform;

    impl system_integration::JailTestPlatform for MacOSPlatform {
        fn require_privileges() {
            common::require_sudo();
        }

        fn platform_name() -> &'static str {
            "macOS"
        }

        fn supports_https_interception() -> bool {
            true // macOS supports transparent TLS interception
        }
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_allows_matching_requests() {
        system_integration::test_jail_allows_matching_requests::<MacOSPlatform>();
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_denies_non_matching_requests() {
        system_integration::test_jail_denies_non_matching_requests::<MacOSPlatform>();
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_method_specific_rules() {
        system_integration::test_jail_method_specific_rules::<MacOSPlatform>();
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_log_only_mode() {
        system_integration::test_jail_log_only_mode::<MacOSPlatform>();
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_dry_run_mode() {
        system_integration::test_jail_dry_run_mode::<MacOSPlatform>();
    }

    #[test]
    fn test_jail_requires_command() {
        system_integration::test_jail_requires_command::<MacOSPlatform>();
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_exit_code_propagation() {
        system_integration::test_jail_exit_code_propagation::<MacOSPlatform>();
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_native_jail_blocks_https() {
        system_integration::test_native_jail_blocks_https::<MacOSPlatform>();
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_native_jail_allows_https() {
        system_integration::test_native_jail_allows_https::<MacOSPlatform>();
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_https_connect_denied() {
        system_integration::test_jail_https_connect_denied::<MacOSPlatform>();
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_https_connect_allowed() {
        system_integration::test_jail_https_connect_allowed::<MacOSPlatform>();
    }
}
