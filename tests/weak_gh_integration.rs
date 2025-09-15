mod common;

#[cfg(not(target_os = "macos"))]
use common::HttpjailCommand;
#[cfg(not(target_os = "macos"))]
use std::process::Command;

// macOS' Go toolchain uses the platform verifier which ignores SSL_CERT_FILE, so
// tls interception in weak mode will fail for Go clients unless we tunnel. Until
// behavior is adjusted, run this on non-macOS only.
#[cfg(not(target_os = "macos"))]
#[test]
fn test_weak_mode_gh_api_zen() {
    // Skip if gh is not available in the environment
    if Command::new("gh").arg("--version").output().is_err() {
        eprintln!("Skipping test: gh CLI not installed");
        return;
    }

    // Allow GitHub API hosts. Use a very permissive allowlist for this test to
    // avoid flakes if gh makes auxiliary calls.
    let allow_js = "['api.github.com','github.com','uploads.github.com','raw.githubusercontent.com'].includes(r.host)";

    let result = HttpjailCommand::new()
        .weak()
        .js(allow_js)
        .verbose(1)
        .command(vec!["gh", "api", "-X", "GET", "/zen"])
        .execute();

    match result {
        Ok((exit_code, stdout, stderr)) => {
            println!("exit={}\nstderr={}\n", exit_code, stderr);
            assert_eq!(exit_code, 0, "gh api exited non-zero: {}", stderr);
            assert!(
                !stderr.contains("x509:") && !stderr.to_lowercase().contains("certificate signed by unknown authority"),
                "TLS verification failed under httpjail: {}",
                stderr
            );
            assert!(
                !stdout.trim().is_empty(),
                "Expected non-empty /zen response, got empty stdout"
            );
        }
        Err(e) => panic!("Failed to execute httpjail with gh: {}", e),
    }
}
