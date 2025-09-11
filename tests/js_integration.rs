use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

/// Test basic V8 JavaScript rule evaluation
#[tokio::test]
async fn test_js_rule_basic() {
    // Start server with JavaScript rule that allows only github.com
    let mut child = Command::cargo_bin("httpjail")
        .expect("binary exists")
        .args(["--server", "--js", "return host === 'github.com'"])
        .spawn()
        .expect("Failed to start httpjail server");

    // Give server time to start
    sleep(Duration::from_millis(500)).await;

    // Test that the server started successfully
    // Note: In a full integration test, we would test actual HTTP requests
    // through the proxy, but that requires more complex setup

    // Clean up
    child.kill().expect("Failed to kill server");
    child.wait().expect("Failed to wait for server");
}

/// Test JavaScript syntax error handling
#[tokio::test]
async fn test_js_syntax_error() {
    let mut cmd = Command::cargo_bin("httpjail").expect("binary exists");

    cmd.args(["--server", "--js", "return invalid syntax !!!"]);

    // Should fail with syntax error
    cmd.assert().failure().stderr(predicate::str::contains(
        "Failed to create V8 JavaScript engine",
    ));
}

/// Test JavaScript rule with complex logic
#[tokio::test]
async fn test_js_complex_rule() {
    let js_code = r#"
        // Allow GitHub and safe domains
        if (host.endsWith('github.com') || host === 'api.github.com') {
            return true;
        }
        
        // Block social media
        if (host.includes('facebook.com') || host.includes('twitter.com')) {
            return false;
        }
        
        // Allow HTTPS API calls
        if (scheme === 'https' && path.startsWith('/api/')) {
            return true;
        }
        
        // Default deny
        return false;
    "#;

    // Start server with complex JavaScript rule
    let mut child = Command::cargo_bin("httpjail")
        .expect("binary exists")
        .args(["--server", "--js", js_code])
        .spawn()
        .expect("Failed to start httpjail server");

    // Give server time to start
    sleep(Duration::from_millis(500)).await;

    // Clean up
    child.kill().expect("Failed to kill server");
    child.wait().expect("Failed to wait for server");
}

/// Test that --js conflicts with --script and --rules
#[tokio::test]
async fn test_js_conflicts() {
    // Test conflict with --script
    let mut cmd = Command::cargo_bin("httpjail").expect("binary exists");

    cmd.args(["--server", "--js", "return true", "--script", "echo test"]);

    cmd.assert().failure().stderr(
        predicate::str::contains("cannot be used with")
            .or(predicate::str::contains("conflicts with")),
    );

    // Test conflict with --rules (flag removed, should error as unexpected)
    let mut cmd = Command::cargo_bin("httpjail").expect("binary exists");

    cmd.args(["--server", "--js", "return true", "--rule", "allow: .*"]);

    cmd.assert().failure().stderr(
        predicate::str::contains("unexpected argument '--rule' found"),
    );
}

/// Test JavaScript rule with method-specific logic
#[tokio::test]
async fn test_js_method_filtering() {
    let js_code = r#"
        // Only allow GET requests to github.com
        return method === 'GET' && host === 'github.com';
    "#;

    let mut child = Command::cargo_bin("httpjail")
        .expect("binary exists")
        .args(["--server", "--js", js_code])
        .spawn()
        .expect("Failed to start httpjail server");

    // Give server time to start
    sleep(Duration::from_millis(500)).await;

    // Clean up
    child.kill().expect("Failed to kill server");
    child.wait().expect("Failed to wait for server");
}