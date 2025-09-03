mod common;
mod system_integration;

#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use crate::system_integration::JailTestPlatform;
    use serial_test::serial;

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

    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_jail_allows_matching_requests() {
        system_integration::test_jail_allows_matching_requests::<LinuxPlatform>();
    }

    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_jail_denies_non_matching_requests() {
        system_integration::test_jail_denies_non_matching_requests::<LinuxPlatform>();
    }

    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_jail_method_specific_rules() {
        system_integration::test_jail_method_specific_rules::<LinuxPlatform>();
    }

    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_jail_log_only_mode() {
        system_integration::test_jail_log_only_mode::<LinuxPlatform>();
    }

    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_jail_dry_run_mode() {
        system_integration::test_jail_dry_run_mode::<LinuxPlatform>();
    }

    #[test]
    fn test_jail_requires_command() {
        system_integration::test_jail_requires_command::<LinuxPlatform>();
    }

    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_jail_exit_code_propagation() {
        system_integration::test_jail_exit_code_propagation::<LinuxPlatform>();
    }

    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_native_jail_blocks_https() {
        system_integration::test_native_jail_blocks_https::<LinuxPlatform>();
    }

    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_native_jail_allows_https() {
        system_integration::test_native_jail_allows_https::<LinuxPlatform>();
    }

    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_jail_https_connect_denied() {
        system_integration::test_jail_https_connect_denied::<LinuxPlatform>();
    }

    // Linux with network namespaces supports HTTPS CONNECT
    #[test]
    #[serial] // Network namespaces are global state, must run sequentially
    fn test_jail_https_connect_allowed() {
        system_integration::test_jail_https_connect_allowed::<LinuxPlatform>();
    }

    // Linux-specific test: verify namespace cleanup
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
            .filter(|line| line.starts_with("httpjail_"))
            .count();

        // Run httpjail
        let mut cmd = system_integration::httpjail_cmd();
        cmd.arg("-r")
            .arg("allow: .*")
            .arg("--")
            .arg("echo")
            .arg("test");

        let _output = cmd.output().expect("Failed to execute httpjail");

        // Check namespaces are cleaned up
        let output = std::process::Command::new("ip")
            .args(&["netns", "list"])
            .output()
            .expect("Failed to list namespaces");

        let final_namespaces = String::from_utf8_lossy(&output.stdout);
        let final_count = final_namespaces
            .lines()
            .filter(|line| line.starts_with("httpjail_"))
            .count();

        assert_eq!(
            initial_count, final_count,
            "Namespace was not cleaned up properly. Initial: {}, Final: {}",
            initial_count, final_count
        );
    }

    // Linux-specific test: verify concurrent execution
    #[test]
    #[serial]
    fn test_concurrent_namespace_isolation() {
        LinuxPlatform::require_privileges();

        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        let success_count = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        // Spawn multiple httpjail instances concurrently
        for i in 0..3 {
            let success_count = Arc::clone(&success_count);
            let handle = thread::spawn(move || {
                let mut cmd = system_integration::httpjail_cmd();
                cmd.arg("-r")
                    .arg("allow: .*")
                    .arg("--")
                    .arg("sh")
                    .arg("-c")
                    .arg(&format!("echo 'Instance {}'", i));

                match cmd.output() {
                    Ok(output) if output.status.success() => {
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // All instances should succeed
        assert_eq!(
            success_count.load(Ordering::SeqCst),
            3,
            "Not all concurrent instances succeeded"
        );

        // Verify all namespaces are cleaned up
        let output = std::process::Command::new("ip")
            .args(&["netns", "list"])
            .output()
            .expect("Failed to list namespaces");

        let namespaces = String::from_utf8_lossy(&output.stdout);
        let httpjail_count = namespaces
            .lines()
            .filter(|line| line.starts_with("httpjail_"))
            .count();

        assert_eq!(
            httpjail_count, 0,
            "Found {} httpjail namespaces still present after concurrent test",
            httpjail_count
        );
    }
}

#[cfg(not(target_os = "linux"))]
mod tests {
    #[test]
    fn test_platform_not_linux() {
        println!("Linux integration tests only run on Linux");
    }
}
