use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_httpjail_help() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--help");

    cmd.assert().success().stdout(predicate::str::contains(
        "Monitor and restrict HTTP/HTTPS requests",
    ));
}

#[test]
fn test_httpjail_version() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("--version");
    let hash = env!("GIT_HASH");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("httpjail").and(predicate::str::contains(hash)));
}

#[test]
fn test_httpjail_requires_command() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    // original command: cmd.arg("-r").arg("exit 1;");
    cmd.arg("--js").arg("true");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_httpjail_invalid_js_syntax() {
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    // original testing with invalid regex: cmd.arg("-r").arg("invalid[regex");
    cmd.arg("--js")
        .arg("invalid syntax !!!")
        .arg("--")
        .arg("echo")
        .arg("test");

    // Should fail due to invalid JS
    cmd.assert().failure();
}

#[cfg(target_os = "macos")]
#[test]
#[ignore] // Requires sudo
fn test_httpjail_basic_execution() {
    // Simple test that doesn't make network requests
    let mut cmd = Command::cargo_bin("httpjail").unwrap();
    cmd.arg("-r")
        .arg("allow: .*")
        .arg("--")
        .arg("echo")
        .arg("Hello from jail");

    // Convert to sudo command
    let mut sudo_cmd = std::process::Command::new("sudo");
    sudo_cmd.arg("-E");
    sudo_cmd.arg(cmd.get_program());
    for arg in cmd.get_args() {
        sudo_cmd.arg(arg);
    }

    let output = sudo_cmd.output().expect("Failed to execute");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Hello from jail"));
    assert!(output.status.success());
}
