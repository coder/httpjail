use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_httpjail_test_flag_allow() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--js")
        .arg("true")
        .arg("--test")
        .arg("https://example.com");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ALLOW GET https://example.com"));
}

#[test]
fn test_httpjail_test_flag_deny() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--js")
        .arg("false")
        .arg("--test")
        .arg("https://example.com");
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("DENY GET https://example.com"));
}
