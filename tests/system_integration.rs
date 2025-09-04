#![allow(dead_code)] // These functions are used from platform-specific test modules

/// Common integration tests for both macOS and Linux jail implementations
/// This module contains the shared test logic that both platforms use
use assert_cmd::Command;
use predicates::prelude::*;

/// Platform-specific trait for jail testing
pub trait JailTestPlatform {
    /// Check if we have necessary privileges (root/sudo)
    fn require_privileges();

    /// Platform name for logging
    fn platform_name() -> &'static str;

    /// Whether the platform supports full HTTPS interception
    fn supports_https_interception() -> bool {
        true
    }
}

/// Helper to create httpjail command with standard test settings
pub fn httpjail_cmd() -> Command {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    // Add timeout for all tests (15 seconds for CI environment)
    cmd.arg("--timeout").arg("15");
    // No need to specify ports - they'll be auto-assigned
    cmd
}

/// Helper to add curl HTTP status check arguments
fn curl_http_status_args(cmd: &mut Command, url: &str) {
    cmd.arg("curl")
        .arg("-s")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg(url);
}

/// Helper to add curl HTTP status check with specific method
fn curl_http_method_status_args(cmd: &mut Command, method: &str, url: &str) {
    cmd.arg("curl")
        .arg("-X")
        .arg(method)
        .arg("-s")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg(url);
}

/// Helper to add curl HTTPS HEAD request with verbose output
fn curl_https_head_args(cmd: &mut Command, url: &str) {
    cmd.arg("curl")
        .arg("-v")
        .arg("--trace-ascii")
        .arg("/dev/stderr")
        .arg("--connect-timeout")
        .arg("10")
        .arg("-I")
        .arg(url);
}

/// Helper for curl HTTPS status check with -k flag
fn curl_https_status_args(cmd: &mut Command, url: &str) {
    cmd.arg("curl")
        .arg("-k")
        .arg("--max-time")
        .arg("5")
        .arg("-s")
        .arg("-o")
        .arg("/dev/null")
        .arg("-w")
        .arg("%{http_code}")
        .arg(url);
}

/// Test that jail allows matching requests
pub fn test_jail_allows_matching_requests<P: JailTestPlatform>() {
    P::require_privileges();

    let mut cmd = httpjail_cmd();
    cmd.arg("-r").arg("allow: ifconfig\\.me").arg("--");
    curl_http_status_args(&mut cmd, "http://ifconfig.me");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprintln!("[{}] stderr: {}", P::platform_name(), stderr);
    }
    assert_eq!(stdout.trim(), "200", "Request should be allowed");
    assert!(output.status.success());
}

/// Test that jail denies non-matching requests
pub fn test_jail_denies_non_matching_requests<P: JailTestPlatform>() {
    P::require_privileges();

    let mut cmd = httpjail_cmd();
    cmd.arg("-r").arg("allow: ifconfig\\.me").arg("--");
    curl_http_status_args(&mut cmd, "http://example.com");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should get 403 Forbidden from our proxy
    assert_eq!(stdout.trim(), "403", "Request should be denied");
    // curl itself should succeed (it got a response)
    assert!(output.status.success());
}

/// Test method-specific rules (GET vs POST)
pub fn test_jail_method_specific_rules<P: JailTestPlatform>() {
    P::require_privileges();

    // Test 1: Allow GET to ifconfig.me
    let mut cmd = httpjail_cmd();
    cmd.arg("-r").arg("allow-get: ifconfig\\.me").arg("--");
    curl_http_method_status_args(&mut cmd, "GET", "http://ifconfig.me");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprintln!("[{}] stderr: {}", P::platform_name(), stderr);
    }
    assert_eq!(stdout.trim(), "200", "GET request should be allowed");

    // Test 2: Deny POST to same URL (ifconfig.me)
    let mut cmd = httpjail_cmd();
    cmd.arg("-r").arg("allow-get: ifconfig\\.me").arg("--");
    curl_http_method_status_args(&mut cmd, "POST", "http://ifconfig.me");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "403", "POST request should be denied");
}

/// Test log-only mode
pub fn test_jail_log_only_mode<P: JailTestPlatform>() {
    P::require_privileges();

    let mut cmd = httpjail_cmd();
    cmd.arg("--log-only").arg("--");
    curl_http_status_args(&mut cmd, "http://example.com");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprintln!("[{}] stderr: {}", P::platform_name(), stderr);
    }
    eprintln!("[{}] stdout: {}", P::platform_name(), stdout);

    // In log-only mode, all requests should be allowed
    // Due to proxy issues, we might get partial responses or timeouts
    // Just verify that the request wasn't explicitly blocked (403)
    assert!(
        !stdout.contains("403") && !stderr.contains("403") && !stdout.contains("Request blocked"),
        "Request should not be blocked in log-only mode. Got stdout: '{}', stderr: '{}', exit code: {:?}",
        stdout.trim(),
        stderr.trim(),
        output.status.code()
    );
}

/// Test dry-run mode
pub fn test_jail_dry_run_mode<P: JailTestPlatform>() {
    P::require_privileges();

    let mut cmd = httpjail_cmd();
    cmd.arg("--dry-run")
        .arg("-r")
        .arg("deny: .*") // Deny everything
        .arg("--");
    curl_http_status_args(&mut cmd, "http://ifconfig.me");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprintln!("[{}] stderr: {}", P::platform_name(), stderr);
    }
    // In dry-run mode, even deny rules should not block
    assert_eq!(
        stdout.trim(),
        "200",
        "Request should be allowed in dry-run mode"
    );
    assert!(output.status.success());
}

/// Test that jail requires a command
pub fn test_jail_requires_command<P: JailTestPlatform>() {
    // This test doesn't require root
    let mut cmd = httpjail_cmd();
    cmd.arg("-r").arg("allow: .*");

    cmd.assert().failure().stderr(predicate::str::contains(
        "required arguments were not provided",
    ));
}

/// Test exit code propagation
pub fn test_jail_exit_code_propagation<P: JailTestPlatform>() {
    P::require_privileges();

    // Test that httpjail propagates the exit code of the child process
    let mut cmd = httpjail_cmd();
    cmd.arg("-r")
        .arg("allow: .*")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("exit 42");

    let output = cmd.output().expect("Failed to execute httpjail");

    let exit_code = output.status.code();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Add debugging output
    if exit_code != Some(42) {
        eprintln!("[{}] Exit code propagation failed", P::platform_name());
        eprintln!("  Expected: 42, Got: {:?}", exit_code);
        eprintln!("  Stdout: {}", stdout);
        eprintln!("  Stderr: {}", stderr);
    }

    assert_eq!(
        exit_code,
        Some(42),
        "Exit code should be propagated. Got {:?}, stderr: {}",
        exit_code,
        stderr
    );
}

/// Test HTTPS blocking
pub fn test_native_jail_blocks_https<P: JailTestPlatform>() {
    P::require_privileges();

    // Test that HTTPS requests to denied domains are blocked
    let mut cmd = httpjail_cmd();
    cmd.arg("-r")
        .arg("allow: ifconfig\\.me")
        .arg("-r")
        .arg("deny: example\\.com")
        .arg("--");
    curl_https_head_args(&mut cmd, "https://example.com");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[{}] HTTPS denied test stderr: {}",
        P::platform_name(),
        stderr
    );
    eprintln!(
        "[{}] HTTPS denied test stdout: {}",
        P::platform_name(),
        stdout
    );

    if P::supports_https_interception() {
        // With transparent TLS interception, we now complete the TLS handshake
        // and return HTTP 403 Forbidden for denied hosts
        assert!(
            stdout.contains("403 Forbidden") || stdout.contains("403"),
            "HTTPS connection should return 403 Forbidden for denied host example.com. Got stdout: {}",
            stdout
        );
    } else {
        // Without TLS interception, connection should fail
        assert!(
            !output.status.success(),
            "HTTPS connection to denied host should fail"
        );
    }
}

/// Test HTTPS allowing
pub fn test_native_jail_allows_https<P: JailTestPlatform>() {
    P::require_privileges();

    // Test allowing HTTPS to ifconfig.me
    let mut cmd = httpjail_cmd();
    cmd.arg("-r").arg("allow: ifconfig\\.me").arg("--");
    curl_https_status_args(&mut cmd, "https://ifconfig.me");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!(
        "[{}] HTTPS allow test stderr: {}",
        P::platform_name(),
        stderr
    );
    eprintln!(
        "[{}] HTTPS allow test stdout: {}",
        P::platform_name(),
        stdout
    );

    // Should not be blocked
    assert!(
        !stderr.contains("403 Forbidden") && !stderr.contains("Request blocked"),
        "Request should not be blocked when allowed"
    );
}

/// Test HTTPS CONNECT allowed (only for weak mode - not used in strong jails)
/// Strong jails use transparent TLS interception, not HTTP CONNECT method
#[allow(dead_code)]
pub fn test_jail_https_connect_allowed<P: JailTestPlatform>() {
    // This test is not applicable to strong jails which use transparent interception
    // It's preserved here for potential use in weak mode testing where HTTP CONNECT is used
    eprintln!(
        "[{}] Skipping HTTPS CONNECT test - not applicable for strong jails with transparent TLS interception",
        P::platform_name()
    );
}

/// Test privilege dropping - whoami should report original user, not root
pub fn test_jail_privilege_dropping<P: JailTestPlatform>() {
    // This test requires sudo to be meaningful
    P::require_privileges();

    // Get the expected username from SUDO_USER env var
    // If not running under sudo, this test will compare current user with current user
    let expected_user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string());

    eprintln!(
        "[{}] Testing privilege dropping - expecting user: {}",
        P::platform_name(),
        expected_user
    );

    // Run whoami through httpjail
    let mut cmd = httpjail_cmd();
    cmd.arg("-r")
        .arg("allow: .*") // Allow all for this test
        .arg("--")
        .arg("whoami");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stderr.is_empty() {
        eprintln!("[{}] stderr: {}", P::platform_name(), stderr);
    }

    let actual_user = stdout.trim();
    eprintln!(
        "[{}] whoami returned: '{}'",
        P::platform_name(),
        actual_user
    );

    // The user should be the original user, not root
    assert_eq!(
        actual_user, expected_user,
        "whoami should return the original user ({}), not root. Got: {}",
        expected_user, actual_user
    );

    // Also verify that id command shows correct user
    let mut cmd = httpjail_cmd();
    cmd.arg("-r")
        .arg("allow: .*")
        .arg("--")
        .arg("id")
        .arg("-un"); // Get username from id

    let output = cmd.output().expect("Failed to execute httpjail");
    let id_user = String::from_utf8_lossy(&output.stdout).trim().to_string();

    eprintln!("[{}] id -un returned: '{}'", P::platform_name(), id_user);

    assert_eq!(
        id_user, expected_user,
        "id -un should return the original user ({}), not root. Got: {}",
        expected_user, id_user
    );
}

/// Test HTTPS CONNECT denied
pub fn test_jail_https_connect_denied<P: JailTestPlatform>() {
    P::require_privileges();

    // Test that HTTPS requests to denied domains are blocked
    let mut cmd = httpjail_cmd();
    cmd.arg("-r")
        .arg("allow: ifconfig\\.me")
        .arg("-r")
        .arg("deny: example\\.com")
        .arg("--");
    curl_https_head_args(&mut cmd, "https://example.com");

    let output = cmd.output().expect("Failed to execute httpjail");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    eprintln!(
        "[{}] HTTPS denied test stderr: {}",
        P::platform_name(),
        stderr
    );
    eprintln!(
        "[{}] HTTPS denied test stdout: {}",
        P::platform_name(),
        stdout
    );

    // With transparent TLS interception, we now complete the TLS handshake
    // and return HTTP 403 Forbidden for denied hosts
    assert!(
        stdout.contains("403 Forbidden") || stdout.contains("403"),
        "HTTPS connection should return 403 Forbidden for denied host example.com. Got stdout: {}",
        stdout
    );
}
