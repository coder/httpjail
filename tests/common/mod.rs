use std::process::Command;

/// Build httpjail binary and return the path
pub fn build_httpjail() -> Result<String, String> {
    let output = Command::new("cargo")
        .args(&["build", "--bin", "httpjail"])
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
}

impl HttpjailCommand {
    /// Create a new httpjail command builder
    pub fn new() -> Self {
        Self {
            args: vec![],
            use_sudo: false,
            weak_mode: false,
        }
    }
    
    /// Use weak mode (environment variables only)
    pub fn weak(mut self) -> Self {
        self.weak_mode = true;
        self
    }
    
    /// Use sudo for execution (macOS strong mode)
    pub fn sudo(mut self) -> Self {
        self.use_sudo = true;
        self
    }
    
    /// Add a rule
    pub fn rule(mut self, rule: &str) -> Self {
        self.args.push("-r".to_string());
        self.args.push(rule.to_string());
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
        
        // Always add timeout for tests (10 seconds default)
        self.args.insert(0, "--timeout".to_string());
        self.args.insert(1, "10".to_string());
        
        // Add weak mode if requested
        if self.weak_mode {
            self.args.insert(0, "--weak".to_string());
        }
        
        let mut cmd = if self.use_sudo {
            let mut sudo_cmd = Command::new("sudo");
            
            // Use askpass for macOS if available
            #[cfg(target_os = "macos")]
            if std::path::Path::new("askpass_macos.sh").exists() {
                sudo_cmd.env("SUDO_ASKPASS", format!("{}/askpass_macos.sh", std::env::current_dir().unwrap().display()));
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
    
    /// Build the command without executing (for debugging)
    pub fn build(mut self) -> Vec<String> {
        // Always add timeout for tests
        self.args.insert(0, "--timeout".to_string());
        self.args.insert(1, "10".to_string());
        
        if self.weak_mode {
            self.args.insert(0, "--weak".to_string());
        }
        
        self.args
    }
}

/// Check if running with sudo
pub fn has_sudo() -> bool {
    std::env::var("USER").unwrap_or_default() == "root" || std::env::var("SUDO_USER").is_ok()
}

/// Clean up PF rules on macOS
#[cfg(target_os = "macos")]
pub fn cleanup_pf_rules() {
    let _ = Command::new("sudo")
        .args(&["pfctl", "-a", "httpjail", "-F", "all"])
        .output();
}