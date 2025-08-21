mod common;

use common::{HttpjailCommand, test_https_allow, test_https_blocking};

#[test]
fn test_weak_mode_blocks_https_correctly() {
    // Use the common test function with weak mode (no sudo)
    test_https_blocking(false);
}

#[test]
fn test_weak_mode_allows_https_with_allow_rule() {
    // Use the common test function with weak mode (no sudo)
    test_https_allow(false);
}

#[test]
fn test_weak_mode_blocks_http_correctly() {
    // Test that HTTP to httpbin.org is blocked in weak mode
    let result = HttpjailCommand::new()
        .weak()
        .rule("deny: .*")
        .verbose(2)
        .command(vec!["curl", "--max-time", "3", "http://httpbin.org/get"])
        .execute();

    match result {
        Ok((exit_code, stdout, stderr)) => {
            println!("Exit code: {}", exit_code);
            println!("Stdout: {}", stdout);
            println!("Stderr: {}", stderr);

            // HTTP blocking returns a 403 response, so curl succeeds but with forbidden message
            // Should contain the blocked message
            assert!(
                stdout.contains("Request blocked by httpjail") || exit_code != 0,
                "Expected request to be blocked, but got normal response"
            );

            // Should not contain httpbin.org content
            assert!(!stdout.contains("\"url\""));
            assert!(!stdout.contains("\"args\""));
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}

#[test]
fn test_weak_mode_timeout_works() {
    // Test that the timeout mechanism works correctly
    // This test uses a command that would normally hang
    let result = HttpjailCommand::new()
        .weak()
        .rule("allow: .*")
        .verbose(2)
        .command(vec!["sh", "-c", "sleep 15"])
        .execute();

    match result {
        Ok((exit_code, _stdout, _stderr)) => {
            // Should timeout with exit code 124
            assert_eq!(
                exit_code, 124,
                "Expected timeout exit code 124, got: {}",
                exit_code
            );
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}

#[test]
fn test_weak_mode_allows_localhost() {
    // Test that localhost connections work (for the proxy itself)
    let result = HttpjailCommand::new()
        .weak()
        .rule("allow: localhost")
        .rule("allow: 127\\.0\\.0\\.1")
        .verbose(2)
        .command(vec![
            "curl",
            "--max-time",
            "3",
            "http://127.0.0.1:8080/test",
        ])
        .execute();

    match result {
        Ok((exit_code, _stdout, stderr)) => {
            println!("Exit code: {}", exit_code);
            println!("Stderr: {}", stderr);

            // This should fail with connection refused (no server on 8080)
            // but NOT be blocked by the proxy
            // Exit code 7 = Failed to connect (expected - no server)
            // Exit code 52 = Empty reply from server (proxy allowed but no backend)
            assert!(
                exit_code == 7 || exit_code == 52,
                "Expected connection refused (7) or empty reply (52), got: {}",
                exit_code
            );

            // The error should be about connection, not forbidden
            assert!(
                !stderr.contains("403") && !stderr.contains("Forbidden"),
                "Request should not be forbidden by proxy"
            );
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}
