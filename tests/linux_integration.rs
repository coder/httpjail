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
        cmd.arg("--js")
            .arg("return true;")
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

    /// Comprehensive test to verify all resources are cleaned up after jail execution
    #[test]
    #[serial]
    #[cfg(feature = "isolated-cleanup-tests")]
    fn test_comprehensive_resource_cleanup() {
        LinuxPlatform::require_privileges();

        // 1. Get initial state of all resources

        // Network namespaces
        let initial_namespaces = std::process::Command::new("ip")
            .args(["netns", "list"])
            .output()
            .expect("Failed to list namespaces")
            .stdout;
        let initial_ns_count = String::from_utf8_lossy(&initial_namespaces)
            .lines()
            .filter(|line| line.contains("httpjail_"))
            .count();

        // Virtual ethernet pairs
        let initial_links = std::process::Command::new("ip")
            .args(["link", "show"])
            .output()
            .expect("Failed to list network links")
            .stdout;
        let initial_veth_count = String::from_utf8_lossy(&initial_links)
            .lines()
            .filter(|line| line.contains("vh_") || line.contains("vn_"))
            .count();

        // NFTables tables
        let initial_nft_tables = std::process::Command::new("nft")
            .args(["list", "tables"])
            .output()
            .expect("Failed to list nftables")
            .stdout;
        let initial_nft_count = String::from_utf8_lossy(&initial_nft_tables)
            .lines()
            .filter(|line| line.contains("httpjail_"))
            .count();

        // Namespace config directories
        let initial_netns_dirs = std::fs::read_dir("/etc/netns")
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().contains("httpjail_"))
                    .count()
            })
            .unwrap_or(0);

        // 2. Run httpjail command
        let mut cmd = httpjail_cmd();
        cmd.arg("--js")
            .arg("return true;")
            .arg("--")
            .arg("echo")
            .arg("test");

        let output = cmd.output().expect("Failed to execute httpjail");
        assert!(output.status.success(), "httpjail command failed");

        // 3. Check all resources were cleaned up

        // Network namespaces
        let final_namespaces = std::process::Command::new("ip")
            .args(["netns", "list"])
            .output()
            .expect("Failed to list namespaces")
            .stdout;
        let final_ns_count = String::from_utf8_lossy(&final_namespaces)
            .lines()
            .filter(|line| line.contains("httpjail_"))
            .count();
        assert_eq!(
            initial_ns_count, final_ns_count,
            "Network namespace not cleaned up. Initial: {}, Final: {}",
            initial_ns_count, final_ns_count
        );

        // Virtual ethernet pairs
        let final_links = std::process::Command::new("ip")
            .args(["link", "show"])
            .output()
            .expect("Failed to list network links")
            .stdout;
        let final_veth_count = String::from_utf8_lossy(&final_links)
            .lines()
            .filter(|line| line.contains("vh_") || line.contains("vn_"))
            .count();
        assert_eq!(
            initial_veth_count, final_veth_count,
            "Virtual ethernet pairs not cleaned up. Initial: {}, Final: {}",
            initial_veth_count, final_veth_count
        );

        // NFTables tables
        let final_nft_tables = std::process::Command::new("nft")
            .args(["list", "tables"])
            .output()
            .expect("Failed to list nftables")
            .stdout;
        let final_nft_count = String::from_utf8_lossy(&final_nft_tables)
            .lines()
            .filter(|line| line.contains("httpjail_"))
            .count();
        assert_eq!(
            initial_nft_count, final_nft_count,
            "NFTables not cleaned up. Initial: {}, Final: {}",
            initial_nft_count, final_nft_count
        );

        // Namespace config directories
        let final_netns_dirs = std::fs::read_dir("/etc/netns")
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().contains("httpjail_"))
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            initial_netns_dirs, final_netns_dirs,
            "Namespace config directories not cleaned up. Initial: {}, Final: {}",
            initial_netns_dirs, final_netns_dirs
        );
    }

    /// Test cleanup after abnormal termination (SIGINT)
    #[test]
    #[serial]
    #[cfg(feature = "isolated-cleanup-tests")]
    fn test_cleanup_after_sigint() {
        LinuxPlatform::require_privileges();

        use std::thread;
        use std::time::Duration;

        // Get initial resource counts
        let initial_ns_count = std::process::Command::new("ip")
            .args(["netns", "list"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter(|l| l.contains("httpjail_"))
                    .count()
            })
            .unwrap_or(0);

        // Start httpjail with a long-running command using std::process::Command directly
        let httpjail_path = assert_cmd::cargo::cargo_bin("httpjail");
        let mut child = std::process::Command::new(&httpjail_path)
            .arg("--js")
            .arg("return true;")
            .arg("--")
            .arg("sleep")
            .arg("60")
            .spawn()
            .expect("Failed to spawn httpjail");

        // Give it time to set up resources
        thread::sleep(Duration::from_millis(500));

        // Send SIGINT (which ctrlc handles)
        unsafe {
            libc::kill(child.id() as i32, libc::SIGINT);
        }

        // Wait for process to exit
        let _ = child.wait();

        // Give cleanup a moment to complete
        thread::sleep(Duration::from_millis(500));

        // Check resources were cleaned up
        let final_ns_count = std::process::Command::new("ip")
            .args(["netns", "list"])
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter(|l| l.contains("httpjail_"))
                    .count()
            })
            .unwrap_or(0);

        assert_eq!(
            initial_ns_count, final_ns_count,
            "Resources not cleaned up after SIGINT. Initial namespaces: {}, Final: {}",
            initial_ns_count, final_ns_count
        );
    }

    /// Verify outbound TCP connections to non-HTTP ports are blocked inside the jail
    ///
    /// Uses portquiz.net which listens on all TCP ports and returns an HTTP response,
    /// allowing us to test egress on non-standard ports reliably.
    #[test]
    fn test_outbound_tcp_non_http_blocked() {
        LinuxPlatform::require_privileges();

        // Attempt to connect to portquiz.net on port 81 (non-standard HTTP port)
        // Expectation: connection is blocked by namespace egress filter
        let mut cmd = httpjail_cmd();
        cmd.arg("--js").arg("true") // allow all requests through proxy
            .arg("--")
            .arg("sh")
            .arg("-c")
            .arg("curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 8 http://portquiz.net:81 && echo CONNECTED || echo BLOCKED");

        let output = cmd.output().expect("Failed to execute httpjail");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        eprintln!("[Linux] outbound TCP test stdout: {}", stdout);
        if !stderr.is_empty() {
            eprintln!("[Linux] outbound TCP test stderr: {}", stderr);
        }

        assert!(
            stdout.contains("BLOCKED"),
            "Non-HTTP outbound TCP should be blocked. stdout: {}, stderr: {}",
            stdout.trim(),
            stderr.trim()
        );
    }
}
