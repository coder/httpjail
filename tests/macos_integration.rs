use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    fn check_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn skip_if_not_root() {
        if !check_root() {
            eprintln!("\n⚠️  Test requires root privileges.");
            eprintln!(
                "   Run the entire test suite with: sudo cargo test --test macos_integration -- --ignored"
            );
            eprintln!("   or run httpjail tests directly: sudo $(which cargo) test\n");
            panic!("Test skipped: requires root privileges");
        }
    }

    fn httpjail_cmd() -> Command {
        let mut cmd = Command::cargo_bin("httpjail").unwrap();
        // Tests require sudo on macOS
        cmd.env("RUST_LOG", "httpjail=debug");
        // No need to specify ports - they'll be auto-assigned
        cmd
    }

    #[test]
    #[ignore] // Requires sudo - run with: sudo cargo test -- --ignored
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_allows_matching_requests() {
        skip_if_not_root();

        let mut cmd = httpjail_cmd();
        cmd.arg("-r")
            .arg("allow: httpbin\\.org")
            .arg("--")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://httpbin.org/get");

        let output = cmd.output().expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("stderr: {}", stderr);
        }
        assert_eq!(stdout.trim(), "200", "Request should be allowed");
        assert!(output.status.success());
    }

    #[test]
    #[ignore] // Requires sudo
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_denies_non_matching_requests() {
        skip_if_not_root();

        let mut cmd = httpjail_cmd();
        cmd.arg("-r")
            .arg("allow: httpbin\\.org")
            .arg("--")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://example.com");

        let output = cmd.output().expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should get 403 Forbidden from our proxy
        assert_eq!(stdout.trim(), "403", "Request should be denied");
        // curl itself should succeed (it got a response)
        assert!(output.status.success());
    }

    #[test]
    #[ignore] // Requires sudo
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_method_specific_rules() {
        skip_if_not_root();

        // Test 1: Allow GET to httpbin
        let mut cmd = httpjail_cmd();
        cmd.arg("-r")
            .arg("allow-get: httpbin\\.org")
            .arg("--")
            .arg("curl")
            .arg("-X")
            .arg("GET")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://httpbin.org/get");

        let output = cmd.output().expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("stderr: {}", stderr);
        }
        assert_eq!(stdout.trim(), "200", "GET request should be allowed");

        // Test 2: Deny POST to same URL
        let mut cmd = httpjail_cmd();
        cmd.arg("-r")
            .arg("allow-get: httpbin\\.org")
            .arg("--")
            .arg("curl")
            .arg("-X")
            .arg("POST")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://httpbin.org/post");

        let output = cmd.output().expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "403", "POST request should be denied");
    }

    #[test]
    #[ignore] // Requires sudo
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_log_only_mode() {
        skip_if_not_root();

        let mut cmd = httpjail_cmd();
        cmd.arg("--log-only")
            .arg("--")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://example.com");

        let output = cmd.output().expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("stderr: {}", stderr);
        }
        // In log-only mode, all requests should be allowed
        assert_eq!(
            stdout.trim(),
            "200",
            "Request should be allowed in log-only mode"
        );
        assert!(output.status.success());
    }

    #[test]
    #[ignore] // Requires sudo
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_dry_run_mode() {
        skip_if_not_root();

        let mut cmd = httpjail_cmd();
        cmd.arg("--dry-run")
            .arg("-r")
            .arg("deny: .*") // Deny everything
            .arg("--")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://httpbin.org/get");

        let output = cmd.output().expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("stderr: {}", stderr);
        }
        // In dry-run mode, even deny rules should not block
        assert_eq!(
            stdout.trim(),
            "200",
            "Request should be allowed in dry-run mode"
        );
        assert!(output.status.success());
    }

    #[test]
    fn test_jail_requires_command() {
        // This test doesn't require root
        let mut cmd = httpjail_cmd();
        cmd.arg("-r").arg("allow: .*");

        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("required but not provided"));
    }

    #[test]
    #[ignore] // Requires sudo
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_exit_code_propagation() {
        skip_if_not_root();

        // Test that httpjail propagates the exit code of the child process
        let mut cmd = httpjail_cmd();
        cmd.arg("-r")
            .arg("allow: .*")
            .arg("--")
            .arg("sh")
            .arg("-c")
            .arg("exit 42");

        let output = cmd.output().expect("Failed to execute httpjail");

        assert_eq!(
            output.status.code(),
            Some(42),
            "Exit code should be propagated"
        );
    }

    #[test]
    #[ignore] // Requires sudo - TLS interception not fully implemented yet
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_https_connect_allowed() {
        skip_if_not_root();

        // Test that CONNECT requests to allowed domains succeed
        // Note: Full TLS interception is not yet implemented, so we just test CONNECT
        let mut cmd = httpjail_cmd();
        cmd.arg("-r")
            .arg("allow: example\\.com")
            .arg("--")
            .arg("curl")
            .arg("-v")
            .arg("--connect-timeout")
            .arg("2")
            .arg("-I") // HEAD request only
            .arg("https://example.com"); // HTTPS URL

        let output = cmd.output().expect("Failed to execute httpjail");

        let stderr = String::from_utf8_lossy(&output.stderr);

        eprintln!("HTTPS CONNECT test stderr: {}", stderr);

        // Should see successful CONNECT response even if TLS fails after
        assert!(
            stderr.contains("< HTTP/1.1 200"),
            "CONNECT should be allowed for example.com"
        );
    }

    #[test]
    #[ignore] // Requires sudo
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_https_connect_denied() {
        skip_if_not_root();

        // Test that CONNECT requests to denied domains are blocked
        let mut cmd = httpjail_cmd();
        cmd.arg("-r")
            .arg("allow: httpbin\\.org")
            .arg("-r")
            .arg("deny: example\\.com")
            .arg("--")
            .arg("curl")
            .arg("-v")
            .arg("--connect-timeout")
            .arg("2")
            .arg("-I") // HEAD request only
            .arg("https://example.com"); // HTTPS URL that should be denied

        let output = cmd.output().expect("Failed to execute httpjail");

        let stderr = String::from_utf8_lossy(&output.stderr);

        eprintln!("HTTPS denied test stderr: {}", stderr);

        // Should see 403 Forbidden response to CONNECT
        assert!(
            stderr.contains("< HTTP/1.1 403"),
            "CONNECT should be denied for example.com"
        );
    }
}
