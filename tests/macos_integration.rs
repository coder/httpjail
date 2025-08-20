use assert_cmd::Command;
use predicates::prelude::*;

#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    fn httpjail_cmd() -> Command {
        let mut cmd = Command::cargo_bin("httpjail").unwrap();
        // Tests require sudo on macOS
        cmd.env("RUST_LOG", "httpjail=debug");
        cmd
    }

    fn with_sudo(cmd: Command) -> std::process::Command {
        let mut sudo_cmd = std::process::Command::new("sudo");
        
        // Use askpass if available
        if let Ok(cwd) = std::env::current_dir() {
            let askpass_path = cwd.join("askpass_macos.sh");
            if askpass_path.exists() {
                sudo_cmd.env("SUDO_ASKPASS", askpass_path);
                sudo_cmd.arg("-A");
            }
        }
        
        // Preserve environment for cargo test
        sudo_cmd.arg("-E");
        
        // Get the actual binary path from assert_cmd
        let binary_path = cmd.get_program().to_string_lossy().to_string();
        sudo_cmd.arg(binary_path);
        
        // Add all the arguments
        for arg in cmd.get_args() {
            sudo_cmd.arg(arg);
        }
        
        sudo_cmd
    }

    #[test]
    #[ignore] // Requires sudo - run with: cargo test -- --ignored
    fn test_jail_allows_matching_requests() {
        let mut cmd = httpjail_cmd();
        cmd.arg("--allow")
            .arg("httpbin\\.org")
            .arg("--")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://httpbin.org/get");

        let output = with_sudo(cmd)
            .output()
            .expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("stderr: {}", stderr);
        }
        assert_eq!(stdout.trim(), "200", "Request should be allowed");
        assert!(output.status.success());
    }

    #[test]
    #[ignore] // Requires sudo
    fn test_jail_denies_non_matching_requests() {
        let mut cmd = httpjail_cmd();
        cmd.arg("--allow")
            .arg("httpbin\\.org")
            .arg("--")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://example.com");

        let output = with_sudo(cmd)
            .output()
            .expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should get 403 Forbidden from our proxy
        assert_eq!(stdout.trim(), "403", "Request should be denied");
        // curl itself should succeed (it got a response)
        assert!(output.status.success());
    }

    #[test]
    #[ignore] // Requires sudo
    fn test_jail_method_specific_rules() {
        // Test 1: Allow GET to httpbin
        let mut cmd = httpjail_cmd();
        cmd.arg("--allow-get")
            .arg("httpbin\\.org")
            .arg("--")
            .arg("curl")
            .arg("-X")
            .arg("GET")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://httpbin.org/get");

        let output = with_sudo(cmd)
            .output()
            .expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("stderr: {}", stderr);
        }
        assert_eq!(stdout.trim(), "200", "GET request should be allowed");

        // Test 2: Deny POST to same URL
        let mut cmd = httpjail_cmd();
        cmd.arg("--allow-get")
            .arg("httpbin\\.org")
            .arg("--")
            .arg("curl")
            .arg("-X")
            .arg("POST")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://httpbin.org/post");

        let output = with_sudo(cmd)
            .output()
            .expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "403", "POST request should be denied");
    }

    #[test]
    #[ignore] // Requires sudo
    fn test_jail_log_only_mode() {
        let mut cmd = httpjail_cmd();
        cmd.arg("--log-only")
            .arg("--")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://example.com");

        let output = with_sudo(cmd)
            .output()
            .expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("stderr: {}", stderr);
        }
        // In log-only mode, all requests should be allowed
        assert_eq!(stdout.trim(), "200", "Request should be allowed in log-only mode");
        assert!(output.status.success());
    }

    #[test]
    #[ignore] // Requires sudo
    fn test_jail_dry_run_mode() {
        let mut cmd = httpjail_cmd();
        cmd.arg("--dry-run")
            .arg("--deny")
            .arg(".*")  // Deny everything
            .arg("--")
            .arg("curl")
            .arg("-s")
            .arg("-o")
            .arg("/dev/null")
            .arg("-w")
            .arg("%{http_code}")
            .arg("http://httpbin.org/get");

        let output = with_sudo(cmd)
            .output()
            .expect("Failed to execute httpjail");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprintln!("stderr: {}", stderr);
        }
        // In dry-run mode, even deny rules should not block
        assert_eq!(stdout.trim(), "200", "Request should be allowed in dry-run mode");
        assert!(output.status.success());
    }

    #[test]
    fn test_jail_requires_command() {
        let mut cmd = httpjail_cmd();
        cmd.arg("--allow")
            .arg(".*");
        
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("required but not provided"));
    }

    #[test]
    #[ignore] // Requires sudo
    fn test_jail_exit_code_propagation() {
        // Test that httpjail propagates the exit code of the child process
        let mut cmd = httpjail_cmd();
        cmd.arg("--allow")
            .arg(".*")
            .arg("--")
            .arg("sh")
            .arg("-c")
            .arg("exit 42");

        let output = with_sudo(cmd)
            .output()
            .expect("Failed to execute httpjail");

        assert_eq!(output.status.code(), Some(42), "Exit code should be propagated");
    }
}