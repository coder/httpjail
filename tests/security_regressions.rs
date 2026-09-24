//! Regressions for security-sensitive CLI behavior shared by macOS and Linux.

use std::process::Command;
use std::time::Duration;

#[test]
#[ignore]
fn timeout_marker_child() {
    let Some(marker) = std::env::var_os("HTTPJAIL_TIMEOUT_MARKER") else {
        return;
    };
    std::thread::sleep(Duration::from_secs(2));
    std::fs::write(marker, b"survived").unwrap();
}

#[test]
fn timeout_terminates_child_before_returning() {
    let temp = tempfile::tempdir().unwrap();
    let marker = temp.path().join("survived");
    let child = std::env::current_exe().unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_httpjail"))
        .args(["--weak", "--js", "true", "--timeout", "1", "--"])
        .arg(child)
        .args(["--ignored", "--exact", "timeout_marker_child"])
        .env("HTTPJAIL_TIMEOUT_MARKER", &marker)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(124));
    std::thread::sleep(Duration::from_millis(1200));
    assert!(!marker.exists(), "timed-out child ran after jail cleanup");
}

#[cfg(target_os = "macos")]
#[test]
fn stalled_processor_stdin_times_out() {
    let url = format!("https://example.invalid/{}", "a".repeat(120_000));
    let start = std::time::Instant::now();
    let output = Command::new(env!("CARGO_BIN_EXE_httpjail"))
        .args(["--proc", "/usr/bin/caffeinate", "--test"])
        .env_remove("RUST_LOG")
        .arg(url)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(start.elapsed() < Duration::from_secs(8));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Program evaluation timed out"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn new_request_log_is_private() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("requests.log");
    let mut command = Command::new(env!("CARGO_BIN_EXE_httpjail"));
    command
        .args(["--js", "false", "--request-log"])
        .arg(&path)
        .args(["--test", "https://example.invalid/?token=dummy"]);
    // Set the child umask, not the process-wide test runner umask.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    assert_eq!(command.status().unwrap().code(), Some(1));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
