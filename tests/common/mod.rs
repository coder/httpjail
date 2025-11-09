#![allow(dead_code)] // These are utility functions used across different test modules

pub mod logging; // Automatic test logging setup

use std::process::Command;

/// Construct httpjail command with standard test settings
pub struct HttpjailCommand {
    args: Vec<String>,
    use_sudo: bool,
    weak_mode: bool,
    env: Vec<(String, String)>,
    timeout_secs: u16,
}

impl HttpjailCommand {
    /// Create a new httpjail command builder
    pub fn new() -> Self {
        Self {
            args: vec![],
            use_sudo: false,
            weak_mode: false,
            env: vec![],
            timeout_secs: 15, // Default timeout
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

    /// Use a line processor program (--proc)
    pub fn proc_path(mut self, path: &str) -> Self {
        self.args.push("--proc".to_string());
        self.args.push(path.to_string());
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

    /// Set custom timeout in seconds
    pub fn timeout(mut self, seconds: u16) -> Self {
        self.timeout_secs = seconds;
        self
    }

    /// Build and execute the command
    pub fn execute(mut self) -> Result<(i32, String, String), String> {
        // Use the binary path produced by the same Cargo test build
        let httpjail_path: &str = env!("CARGO_BIN_EXE_httpjail");

        // Always add timeout for tests
        self.args.insert(0, "--timeout".to_string());
        self.args.insert(1, self.timeout_secs.to_string());

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
                        std::env::current_dir().unwrap().to_string_lossy()
                    ),
                );
            }

            sudo_cmd.arg("-E"); // Preserve environment
            sudo_cmd.arg(httpjail_path);
            for arg in &self.args {
                sudo_cmd.arg(arg);
            }
            // Skip automatic keychain installation during tests
            sudo_cmd.env("HTTPJAIL_SKIP_KEYCHAIN_INSTALL", "1");
            for (key, value) in &self.env {
                sudo_cmd.env(key, value);
            }
            sudo_cmd
        } else {
            let mut cmd = Command::new(httpjail_path);
            for arg in &self.args {
                cmd.arg(arg);
            }
            // Skip automatic keychain installation during tests
            cmd.env("HTTPJAIL_SKIP_KEYCHAIN_INSTALL", "1");
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

// Wait until a TCP port on localhost is accepting connections
// Returns true if the port became ready before max_wait elapsed
pub async fn wait_for_server(port: u16, max_wait: std::time::Duration) -> bool {
    let start = tokio::time::Instant::now();
    let poll_interval = tokio::time::Duration::from_millis(75);
    let settle_time = tokio::time::Duration::from_millis(200);

    while start.elapsed() < max_wait {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
        {
            // Give the server a brief moment to finish initialization
            tokio::time::sleep(settle_time).await;
            return true;
        }
        tokio::time::sleep(poll_interval).await;
    }
    false
}
