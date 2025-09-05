mod common;
mod system_integration;

#[macro_use]
mod platform_test_macro;

#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use crate::system_integration::{JailTestPlatform, httpjail_cmd};

    /// Linux-specific platform implementation
    struct LinuxPlatform;

    impl system_integration::JailTestPlatform for LinuxPlatform {
        fn require_privileges() {
            // Check if running as root
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                eprintln!("\n⚠️  Test requires root privileges.");
                eprintln!("   Run with: sudo cargo test --test linux_integration");
                eprintln!("   Or in GitHub Actions, tests run with sudo automatically\n");
                panic!("Test skipped: requires root privileges");
            }
        }

        fn platform_name() -> &'static str {
            "Linux"
        }

        fn supports_https_interception() -> bool {
            true // Linux with network namespaces supports transparent TLS interception
        }
    }

    // Generate all the shared platform tests
    platform_tests!(LinuxPlatform);

    // Linux-specific tests below
    use serial_test::serial;

    /// Linux-specific test: verify namespace cleanup
    #[test]
    #[serial]
    fn test_namespace_cleanup() {
        LinuxPlatform::require_privileges();

        // Get initial namespace count
        let output = std::process::Command::new("ip")
            .args(["netns", "list"])
            .output()
            .expect("Failed to list namespaces");

        let initial_namespaces = String::from_utf8_lossy(&output.stdout);
        let initial_count = initial_namespaces
            .lines()
            .filter(|line| line.contains("httpjail_"))
            .count();

        // Run httpjail
        let mut cmd = httpjail_cmd();
        cmd.arg("-r")
            .arg("allow: .*")
            .arg("--")
            .arg("echo")
            .arg("test");

        let _output = cmd.output().expect("Failed to execute httpjail");

        // Check namespace was cleaned up
        let output = std::process::Command::new("ip")
            .args(["netns", "list"])
            .output()
            .expect("Failed to list namespaces");

        let final_namespaces = String::from_utf8_lossy(&output.stdout);
        let final_count = final_namespaces
            .lines()
            .filter(|line| line.contains("httpjail_"))
            .count();

        assert_eq!(
            initial_count, final_count,
            "Namespace not cleaned up properly. Initial: {}, Final: {}",
            initial_count, final_count
        );
    }
}
