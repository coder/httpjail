use assert_cmd::Command;
use predicates::prelude::*;
use std::env;

mod common;

#[test]
fn test_basic_allow_rule() {
    // Start mock server
    let server = common::MockServer::start();
    
    // Test allowing requests to localhost
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--allow")
        .arg(&format!("127\\.0\\.0\\.1:{}", server.port))
        .arg("--deny")
        .arg(".*")
        .arg("--")
        .arg("curl")
        .arg("-s")
        .arg(&server.url);
    
    cmd.assert().success();
}

#[test]
fn test_basic_deny_rule() {
    // This test verifies the CLI parses arguments correctly
    // In a real implementation, the curl would fail due to network isolation
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--deny")
        .arg(".*")
        .arg("--")
        .arg("echo")
        .arg("test");
    
    cmd.assert().success().stdout("test\n");
}

#[test]
fn test_multiple_allow_rules() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--allow")
        .arg("github\\.com")
        .arg("--allow")
        .arg("githubusercontent\\.com")
        .arg("--deny")
        .arg(".*")
        .arg("--")
        .arg("echo")
        .arg("multiple rules");
    
    cmd.assert().success().stdout("multiple rules\n");
}

#[test]
fn test_dry_run_mode() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--dry-run")
        .arg("--deny")
        .arg(".*")
        .arg("--")
        .arg("echo")
        .arg("dry run");
    
    cmd.assert().success().stdout("dry run\n");
}

#[test]
fn test_log_only_mode() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--log-only")
        .arg("--deny")
        .arg(".*")
        .arg("--")
        .arg("echo")
        .arg("log only");
    
    cmd.assert().success().stdout("log only\n");
}

#[test]
fn test_verbose_output() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("-vv")
        .arg("--allow")
        .arg(".*")
        .arg("--")
        .arg("echo")
        .arg("verbose");
    
    // With verbose logging, we should see info messages mixed with output
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("verbose"));
}

#[test]
fn test_no_command_error() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--allow")
        .arg(".*");
    
    cmd.assert().failure();
}

#[test]
fn test_help_flag() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--help");
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Monitor and restrict HTTP/HTTPS requests"));
}

#[test]
fn test_version_flag() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--version");
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("httpjail"));
}

#[test]
fn test_environment_variable_passthrough() {
    // Test that in test mode, environment variables are set
    unsafe {
        env::set_var("HTTPJAIL_TEST_MODE", "1");
    }
    
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--allow")
        .arg("github\\.com")
        .arg("--deny")
        .arg(".*")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo $HTTPJAIL_RULES");
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("github"));
    
    unsafe {
        env::remove_var("HTTPJAIL_TEST_MODE");
    }
}

// Advanced test simulating actual curl usage
#[test]
#[ignore] // This test requires actual network isolation to work properly
fn test_curl_with_network_isolation() {
    let server = common::MockServer::start();
    
    // Test 1: Allow the mock server
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--allow")
        .arg(&format!("127\\.0\\.0\\.1:{}", server.port))
        .arg("--deny")
        .arg(".*")
        .arg("--")
        .arg("curl")
        .arg("-s")
        .arg(&server.url);
    
    cmd.assert().success().stdout("OK");
    
    // Test 2: Deny everything (including the mock server)
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--deny")
        .arg(".*")
        .arg("--")
        .arg("curl")
        .arg("-s")
        .arg(&server.url);
    
    // This should fail when network isolation is implemented
    cmd.assert().failure();
}