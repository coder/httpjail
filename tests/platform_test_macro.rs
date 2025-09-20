/// Macro to generate platform-specific test functions that delegate to shared implementations
#[macro_export]
macro_rules! platform_tests {
    ($platform:ty) => {
        #[test]
        #[::serial_test::serial]
        fn test_jail_network_diagnostics() {
            system_integration::test_jail_network_diagnostics::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_allows_matching_requests() {
            system_integration::test_jail_allows_matching_requests::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_denies_non_matching_requests() {
            system_integration::test_jail_denies_non_matching_requests::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_method_specific_rules() {
            system_integration::test_jail_method_specific_rules::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_request_log() {
            system_integration::test_jail_request_log::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_requires_command() {
            system_integration::test_jail_requires_command::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_exit_code_propagation() {
            system_integration::test_jail_exit_code_propagation::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_native_jail_allows_https() {
            system_integration::test_native_jail_allows_https::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_native_jail_blocks_https() {
            system_integration::test_native_jail_blocks_https::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_https_connect_denied() {
            system_integration::test_jail_https_connect_denied::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_https_connect_allowed() {
            system_integration::test_jail_https_connect_allowed::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_privilege_dropping() {
            system_integration::test_jail_privilege_dropping::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_concurrent_jail_isolation() {
            system_integration::test_concurrent_jail_isolation::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_jail_dns_resolution() {
            system_integration::test_jail_dns_resolution::<$platform>();
        }

        #[test]
        #[::serial_test::serial]
        fn test_dns_exfiltration_prevention() {
            system_integration::test_dns_exfiltration_prevention::<$platform>();
        }
    };
}
