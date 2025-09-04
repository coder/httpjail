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
            .args(&["netns", "list"])
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
            .args(&["netns", "list"])
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

    /// Linux-specific test: verify concurrent namespace isolation
    #[test]
    #[serial]
    fn test_concurrent_namespace_isolation() {
        LinuxPlatform::require_privileges();
        use std::thread;
        use std::time::Duration;

        // Use assert_cmd to properly find the httpjail binary
        let httpjail_path = assert_cmd::cargo::cargo_bin("httpjail");

        let child1 = std::process::Command::new(&httpjail_path)
            .arg("-r")
            .arg("allow: .*")
            .arg("--")
            .arg("sh")
            .arg("-c")
            .arg("echo Instance1 && sleep 2 && echo Instance1Done")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("Failed to start first httpjail");

        // Give it time to set up
        thread::sleep(Duration::from_millis(500));

        // Start second httpjail instance
        let output2 = std::process::Command::new(&httpjail_path)
            .arg("-r")
            .arg("allow: .*")
            .arg("--")
            .arg("echo")
            .arg("Instance2")
            .output()
            .expect("Failed to execute second httpjail");

        // Both should succeed without interference
        let output1 = child1
            .wait_with_output()
            .expect("Failed to wait for first httpjail");

        assert!(
            output1.status.success(),
            "First instance failed: {:?}",
            String::from_utf8_lossy(&output1.stderr)
        );
        assert!(
            output2.status.success(),
            "Second instance failed: {:?}",
            String::from_utf8_lossy(&output2.stderr)
        );

        // Verify both ran - check both stdout and stderr since output location may vary
        let stdout1 = String::from_utf8_lossy(&output1.stdout);
        let stderr1 = String::from_utf8_lossy(&output1.stderr);
        let stdout2 = String::from_utf8_lossy(&output2.stdout);
        let stderr2 = String::from_utf8_lossy(&output2.stderr);

        assert!(
            stdout1.contains("Instance1") || stderr1.contains("Instance1"),
            "First instance didn't run. stdout: {}, stderr: {}",
            stdout1,
            stderr1
        );
        assert!(
            stdout2.contains("Instance2") || stderr2.contains("Instance2"),
            "Second instance didn't run. stdout: {}, stderr: {}",
            stdout2,
            stderr2
        );
    }
}
