// <--- Begin of necessary code edit

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

#[test]
fn test_httpjail_test_flag_with_post_method() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--js")
        .arg("r.method === 'POST'")
        .arg("--test")
        .arg("POST https://example.com/api");
    cmd.assert().success().stdout(predicate::str::contains(
        "ALLOW POST https://example.com/api",
    ));
}

#[test]
fn test_httpjail_test_flag_with_delete_method() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--js")
        .arg("r.method === 'DELETE'")
        .arg("--test")
        .arg("DELETE https://example.com/resource");
    cmd.assert().success().stdout(predicate::str::contains(
        "ALLOW DELETE https://example.com/resource",
    ));
}

#[test]
fn test_httpjail_test_flag_with_method_deny() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--js")
        .arg("r.method === 'GET'")
        .arg("--test")
        .arg("POST https://example.com");
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("DENY POST https://example.com"));
}

#[test]
fn test_httpjail_test_flag_default_get() {
    // When no method is specified, it should default to GET
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--js")
        .arg("r.method === 'GET'")
        .arg("--test")
        .arg("https://example.com");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ALLOW GET https://example.com"));
}

// <--- End of necessary code edit
