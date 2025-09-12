#![allow(dead_code)] // These are utility functions used across different test modules

use std::process::Command;
use std::sync::OnceLock;

fn resolve_cargo_path() -> String {
    if let Ok(p) = std::env::var("CARGO")
        && !p.is_empty()
        && std::path::Path::new(&p).exists()
    {
        return p;
    }

    if let Ok(ch) = std::env::var("CARGO_HOME") {
        let p = format!("{}/bin/cargo", ch);
        if std::path::Path::new(&p).exists() {
            return p;
        }
    }

    if let Ok(h) = std::env::var("HOME") {
        let p = format!("{}/.cargo/bin/cargo", h);
        if std::path::Path::new(&p).exists() {
            return p;
        }
    }

    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let p = format!("/home/{}/.cargo/bin/cargo", sudo_user);
        if std::path::Path::new(&p).exists() {
            return p;
        }
    }

    "cargo".to_string()
}

fn find_httpjail_in_target_dir(base: &std::path::Path) -> Option<String> {
    let mut stack = vec![base.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(read) = std::fs::read_dir(&dir) {
            for entry in read.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if name == "httpjail" && path.is_file() {
                        return Some(path.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    None
}

static BUILD_RESULT: OnceLock<Result<String, String>> = OnceLock::new();

/// Build httpjail binary and return the path
pub fn build_httpjail() -> Result<String, String> {
    BUILD_RESULT
        .get_or_init(|| {
            // Always build to avoid accidentally using a stale binary
            let cargo = resolve_cargo_path();
            let output = Command::new(&cargo)
                .args(["build", "--bin", "httpjail", "--message-format", "json"])
                .output()
                .map_err(|e| {
                    format!(
                        "Failed to execute '{} build --bin httpjail': {}. \n\
                        Ensure cargo is installed and accessible.",
                        cargo, e
                    )
                });

            match output {
                Ok(output) if output.status.success() => {
                    // Try to parse the executable path from cargo JSON messages
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                            let reason = v.get("reason").and_then(|r| r.as_str()).unwrap_or("");
                            if reason == "compiler-artifact" {
                                if let Some(exec) = v.get("executable").and_then(|e| e.as_str()) {
                                    if !exec.is_empty() && std::path::Path::new(exec).exists() {
                                        eprintln!("Successfully built httpjail binary at {}", exec);
                                        return Ok(exec.to_string());
                                    }
                                }
                            }
                        }
                    }

                    // Fallback: search target directory recursively
                    let target_dir =
                        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
                    let base = std::path::Path::new(&target_dir);
                    if let Some(found) = find_httpjail_in_target_dir(base) {
                        eprintln!("Successfully found httpjail binary at {}", found);
                        return Ok(found);
                    }

                    // Provide diagnostics
                    Err(format!(
                        "Build succeeded but could not locate httpjail executable.\n\
                        Current directory: {:?}\n\
                        CARGO_TARGET_DIR: {:?}\n\
                        Searched under: {:?}\n\
                        Raw cargo stdout (truncated):\n{}",
                        std::env::current_dir()
                            .unwrap_or_else(|_| std::path::PathBuf::from("unknown")),
                        std::env::var("CARGO_TARGET_DIR").ok(),
                        base,
                        stdout.lines().take(50).collect::<Vec<_>>().join("\n")
                    ))
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(format!(
                        "Failed to build httpjail binary. Build output:\n{}",
                        stderr
                    ))
                }
                Err(e) => Err(e),
            }
        })
        .clone()
}

/// Construct httpjail command with standard test settings
pub struct HttpjailCommand {
    args: Vec<String>,
    use_sudo: bool,
    weak_mode: bool,
    env: Vec<(String, String)>,
}

impl HttpjailCommand {
    /// Create a new httpjail command builder
    pub fn new() -> Self {
        Self {
            args: vec![],
            use_sudo: false,
            weak_mode: false,
            env: vec![],
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

    /// Provide JavaScript rule code directly
    pub fn js(mut self, code: &str) -> Self {
        self.args.push("--js".to_string());
        self.args.push(code.to_string());
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

    /// Set an environment variable for the httpjail process
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_string(), value.to_string()));
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
            for (key, value) in &self.env {
                sudo_cmd.env(key, value);
            }
            sudo_cmd
        } else {
            let mut cmd = Command::new(&httpjail_path);
            for arg in &self.args {
                cmd.arg(arg);
            }
            for (key, value) in &self.env {
                cmd.env(key, value);
            }
            cmd
        };

        let output = cmd.output().map_err(|e| {
            format!(
                "Failed to execute httpjail at '{}': {}. \n\
                    Current directory: {:?}",
                httpjail_path,
                e,
                std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("unknown"))
            )
        })?;

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
        .js("false")
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

/// Test that HTTPS is allowed with proper JS rule
pub fn test_https_allow(use_sudo: bool) {
    let mut cmd = HttpjailCommand::new();

    if use_sudo {
        cmd = cmd.sudo();
    } else {
        cmd = cmd.weak();
    }

    let result = cmd
        .js("/ifconfig\\.me/.test(r.host)")
        .verbose(2)
        .command(vec!["curl", "-k", "--max-time", "8", "https://ifconfig.me"])
        .execute();

    match result {
        Ok((exit_code, stdout, stderr)) => {
            println!("HTTPS allow test - Exit code: {}", exit_code);
            println!("Stdout: {}", stdout);
            println!("Stderr: {}", stderr);

            if use_sudo {
                assert!(
                    !stderr.contains("403 Forbidden") && !stderr.contains("Request blocked"),
                    "Request should not be blocked when allowed"
                );
            } else {
                assert_eq!(
                    exit_code, 0,
                    "Expected curl to succeed in weak mode, got exit code: {}",
                    exit_code
                );

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
