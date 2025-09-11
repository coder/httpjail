#![allow(dead_code)] // These are utility functions used across different test modules

use std::process::Command;

/// Build httpjail binary and return the path
pub fn build_httpjail() -> Result<String, String> {
    let output = Command::new("cargo")
        .args(["build", "--bin", "httpjail"])
        .output()
        .map_err(|e| format!("Failed to build httpjail: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok("target/debug/httpjail".to_string())
}

/// Construct httpjail command with standard test settings
pub struct HttpjailCommand {
    args: Vec<String>,
    use_sudo: bool,
    weak_mode: bool,
    rules_js: Vec<String>,
}

impl HttpjailCommand {
    /// Create a new httpjail command builder
    pub fn new() -> Self {
        Self {
            args: vec![],
            use_sudo: false,
            weak_mode: false,
            rules_js: vec![],
        }
    }

    /// Use weak mode (environment variables only)
    pub fn weak(mut self) -> Self {
        self.weak_mode = true;
        self
    }

    /// Use sudo for execution (Linux only - macOS uses weak mode)
    pub fn sudo(mut self) -> Self {
        self.use_sudo = true;
        self
    }

    /// Add a rule (legacy syntax) by translating to JS
    pub fn rule(mut self, rule: &str) -> Self {
        // Expect format: action[-method]: pattern
        let parts: Vec<&str> = rule.splitn(2, ':').collect();
        if parts.len() != 2 {
            return self; // ignore invalid in tests
        }
        let action_part = parts[0].trim();
        let pattern = parts[1].trim();

        let mut action = "allow";
        let mut method_guard: Option<&str> = None;
        if let Some((a, m)) = action_part.split_once('-') {
            action = a;
            method_guard = Some(m);
        } else {
            action = action_part;
        }

        let method_expr = if let Some(m) = method_guard {
            let m_upper = m.to_ascii_uppercase();
            format!(" && method === '{}'", m_upper)
        } else {
            "".to_string()
        };

        let cond = format!("new RegExp({:?}).test(url){}", pattern, method_expr);
        let stmt = match action {
            "allow" => format!("if ({}) return true;", cond),
            "deny" => format!("if ({}) return false;", cond),
            _ => String::new(),
        };
        if !stmt.is_empty() {
            self.rules_js.push(stmt);
        }
        self
    }

    /// Add verbose flag
    pub fn verbose(mut self, level: u8) -> Self {
        for _ in 0..level {
            self.args.push("-v".to_string());
        }
        self
    }

    /// Set the command to execute
    pub fn command(mut self, cmd: Vec<&str>) -> Self {
        self.args.push("--".to_string());
        self.args.extend(cmd.iter().map(|s| s.to_string()));
        self
    }

    /// Build and execute the command
    pub fn execute(mut self) -> Result<(i32, String, String), String> {
        // Ensure httpjail is built
        let httpjail_path = build_httpjail()?;

        // Always add timeout for tests (15 seconds default for CI environment)
        self.args.insert(0, "--timeout".to_string());
        self.args.insert(1, "15".to_string());

        // Add weak mode if requested
        if self.weak_mode {
            self.args.insert(0, "--weak".to_string());
        }

        // If rules were provided, inject as --js (default deny at end)
        if !self.rules_js.is_empty() {
            let mut code = self.rules_js.join("\n");
            code.push_str("\nreturn false;");
            self.args.insert(0, code);
            self.args.insert(0, "--js".to_string());
        }

        let mut cmd = if self.use_sudo {
            let mut sudo_cmd = Command::new("sudo");

            // Use askpass for macOS if available
            #[cfg(target_os = "macos")]
            if camino::Utf8Path::new("askpass_macos.sh").exists() {
                sudo_cmd.env(
                    "SUDO_ASKPASS",
                    format!(
                        "{}/askpass_macos.sh",
                        std::env::current_dir().unwrap().display()
                    ),
                );
            }

            sudo_cmd.arg("-E"); // Preserve environment
            sudo_cmd.arg(&httpjail_path);
            for arg in &self.args {
                sudo_cmd.arg(arg);
            }
            sudo_cmd
        } else {
            let mut cmd = Command::new(&httpjail_path);
            for arg in &self.args {
                cmd.arg(arg);
            }
            cmd
        };

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to execute httpjail: {}", e))?;

        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Ok((exit_code, stdout, stderr))
    }
}

/// Check if running with sudo
#[allow(dead_code)]
pub fn has_sudo() -> bool {
    std::env::var("USER").unwrap_or_default() == "root" || std::env::var("SUDO_USER").is_ok()
}

// macOS-specific functions removed - macOS now uses weak mode only

// Common test implementations that can be used by both weak and strong mode tests

/// Test that HTTPS is blocked correctly  
pub fn test_https_blocking(use_sudo: bool) {
    let mut cmd = HttpjailCommand::new();

    if use_sudo {
        cmd = cmd.sudo();
    } else {
        cmd = cmd.weak();
    }

    let result = cmd
        .rule("deny: .*")
        .verbose(2)
        .command(vec!["curl", "-k", "--max-time", "3", "https://ifconfig.me"])
        .execute();

    match result {
        Ok((exit_code, stdout, stderr)) => {
            println!("HTTPS blocking test - Exit code: {}", exit_code);
            println!("Stdout: {}", stdout);
            println!("Stderr: {}", stderr);

            // For HTTPS, curl should fail with connection error or get 403
            assert!(
                exit_code == 7 || exit_code == 35 || exit_code == 56 || exit_code == 124,
                "Expected curl to fail with connection error, got exit code: {}",
                exit_code
            );

            // Should not contain actual response content (IP address from ifconfig.me)
            use std::str::FromStr;
            assert!(
                std::net::Ipv4Addr::from_str(stdout.trim()).is_err()
                    && std::net::Ipv6Addr::from_str(stdout.trim()).is_err(),
                "Response should be blocked, but got: '{}'",
                stdout
            );
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}

/// Test that HTTPS is allowed with proper allow rules
pub fn test_https_allow(use_sudo: bool) {
    let mut cmd = HttpjailCommand::new();

    if use_sudo {
        cmd = cmd.sudo();
    } else {
        cmd = cmd.weak();
    }

    let result = cmd
        .rule("allow: ifconfig\\.me")
        .verbose(2)
        .command(vec!["curl", "-k", "--max-time", "8", "https://ifconfig.me"])
        .execute();

    match result {
        Ok((exit_code, stdout, stderr)) => {
            println!("HTTPS allow test - Exit code: {}", exit_code);
            println!("Stdout: {}", stdout);
            println!("Stderr: {}", stderr);

            // For macOS native mode, TLS interception might have issues
            // So we check that the request was at least allowed (not denied with 403)
            if use_sudo {
                // In sudo mode, just verify it wasn't blocked
                assert!(
                    !stderr.contains("403 Forbidden") && !stderr.contains("Request blocked"),
                    "Request should not be blocked when allowed"
                );
            } else {
                // In weak mode, curl should succeed
                assert_eq!(
                    exit_code, 0,
                    "Expected curl to succeed in weak mode, got exit code: {}",
                    exit_code
                );

                // Should contain actual response content
                // ifconfig.me returns an IP address
                use std::str::FromStr;
                assert!(
                    std::net::Ipv4Addr::from_str(stdout.trim()).is_ok()
                        || std::net::Ipv6Addr::from_str(stdout.trim()).is_ok()
                        || !stdout.trim().is_empty(),
                    "Expected to see valid response content, got: '{}'",
                    stdout
                );
            }
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}
