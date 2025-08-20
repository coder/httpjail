mod common;

use common::HttpjailCommand;

#[test]
fn test_weak_mode_blocks_https_correctly() {
    // Test that HTTPS to example.com is blocked in weak mode
    let result = HttpjailCommand::new()
        .weak()
        .rule("deny: .*")
        .verbose(2)
        .command(vec!["curl", "-k", "--max-time", "3", "https://example.com"])
        .execute();
    
    match result {
        Ok((exit_code, stdout, stderr)) => {
            println!("Exit code: {}", exit_code);
            println!("Stdout: {}", stdout);
            println!("Stderr: {}", stderr);
            
            // curl should fail with a connection error or similar
            // Exit code 7 = Failed to connect
            // Exit code 35 = SSL connect error  
            // Exit code 56 = Failure in receiving network data
            // Exit code 124 = timeout (from our wrapper)
            assert!(
                exit_code == 7 || exit_code == 35 || exit_code == 56 || exit_code == 124,
                "Expected curl to fail with connection error, got exit code: {}",
                exit_code
            );
            
            // Should not contain the example.com content
            assert!(!stdout.contains("<!doctype html>"));
            assert!(!stdout.contains("Example Domain"));
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}

#[test]
fn test_weak_mode_allows_https_with_allow_rule() {
    // Test that HTTPS is allowed when we have an allow rule
    let result = HttpjailCommand::new()
        .weak()
        .rule("allow: example\\.com")
        .verbose(2)
        .command(vec!["curl", "-k", "--max-time", "3", "https://example.com"])
        .execute();
    
    match result {
        Ok((exit_code, stdout, stderr)) => {
            println!("Exit code: {}", exit_code);
            println!("Stdout: {}", stdout);
            println!("Stderr: {}", stderr);
            
            // curl should succeed
            assert_eq!(exit_code, 0, "Expected curl to succeed, got exit code: {}", exit_code);
            
            // Should contain example.com content
            assert!(
                stdout.contains("Example Domain") || stdout.contains("example.com"),
                "Expected to see example.com content in response"
            );
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}

#[test]
fn test_weak_mode_blocks_http_correctly() {
    // Test that HTTP to example.com is blocked in weak mode
    let result = HttpjailCommand::new()
        .weak()
        .rule("deny: .*")
        .verbose(2)
        .command(vec!["curl", "--max-time", "3", "http://example.com"])
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
            
            // Should not contain the example.com content
            assert!(!stdout.contains("<!doctype html>"));
            assert!(!stdout.contains("Example Domain"));
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
        .command(vec!["curl", "--max-time", "3", "http://127.0.0.1:8080/test"])
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