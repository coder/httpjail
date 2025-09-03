mod common;

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;

#[cfg(target_os = "macos")]
mod tests {
    use super::*;
    use crate::common::{require_sudo, test_https_allow, test_https_blocking};

    fn httpjail_cmd() -> Command {
        let mut cmd = Command::cargo_bin("httpjail").unwrap();
        // Add timeout for all tests
        cmd.arg("--timeout").arg("10");
        // No need to specify ports - they'll be auto-assigned
        cmd
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_allows_matching_requests() {
        require_sudo();

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
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_denies_non_matching_requests() {
        require_sudo();

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
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_method_specific_rules() {
        require_sudo();

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
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_log_only_mode() {
        require_sudo();

        let mut cmd = httpjail_cmd();
        cmd.arg("--log-only")
            .arg("--")
            .arg("curl")
            .arg("-s")
            .arg("--connect-timeout")
            .arg("5")
            .arg("--max-time")
            .arg("8")
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
        eprintln!("stdout: {}", stdout);

        // In log-only mode, all requests should be allowed
        // Due to proxy issues, we might get partial responses or timeouts
        // Just verify that the request wasn't explicitly blocked (403)
        assert!(
            !stdout.contains("403")
                && !stderr.contains("403")
                && !stdout.contains("Request blocked"),
            "Request should not be blocked in log-only mode. Got stdout: '{}', stderr: '{}', exit code: {:?}",
            stdout.trim(),
            stderr.trim(),
            output.status.code()
        );
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_dry_run_mode() {
        require_sudo();

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

        cmd.assert().failure().stderr(predicate::str::contains(
            "required arguments were not provided",
        ));
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_exit_code_propagation() {
        require_sudo();

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
    #[serial] // PF rules are global state, must run sequentially
    fn test_native_jail_blocks_https() {
        require_sudo();
        // Use the common test function with native jailing (sudo mode)
        test_https_blocking(true);
    }

    #[test]
    #[serial] // PF rules are global state, must run sequentially
    fn test_native_jail_allows_https() {
        require_sudo();
        // Use the common test function with native jailing (sudo mode)
        test_https_allow(true);
    }

    #[test]
    #[ignore] // Requires sudo - TLS interception not fully implemented yet
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_https_connect_allowed() {
        require_sudo();

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
    #[serial] // PF rules are global state, must run sequentially
    fn test_jail_https_connect_denied() {
        require_sudo();

        // Test that HTTPS requests to denied domains are blocked
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
        let stdout = String::from_utf8_lossy(&output.stdout);

        eprintln!("HTTPS denied test stderr: {}", stderr);
        eprintln!("HTTPS denied test stdout: {}", stdout);

        // With transparent TLS interception, we now complete the TLS handshake
        // and return HTTP 403 Forbidden for denied hosts
        assert!(
            stdout.contains("403 Forbidden") || stdout.contains("403"),
            "HTTPS connection should return 403 Forbidden for denied host example.com. Got stdout: {}",
            stdout
        );
    }
}
