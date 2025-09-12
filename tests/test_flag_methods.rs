use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_httpjail_test_flag_method_two_args() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--js")
        .arg("r.method === 'POST' && r.host === 'example.com'")
        .arg("--test")
        .arg("POST")
        .arg("https://example.com");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ALLOW POST https://example.com"));
}

#[test]
fn test_httpjail_test_flag_method_one_arg_with_space() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--js")
        .arg("r.method === 'PUT' && r.host === 'example.com'")
        .arg("--test")
        .arg("PUT https://example.com");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ALLOW PUT https://example.com"));
}

#[test]
fn test_httpjail_test_flag_method_case_insensitive() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--js")
        .arg("r.method === 'DELETE' && r.host === 'example.com'")
        .arg("--test")
        .arg("delete")
        .arg("https://example.com");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ALLOW DELETE https://example.com"));
}
