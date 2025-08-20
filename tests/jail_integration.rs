#[cfg(target_os = "macos")]
mod macos_jail_integration {
    use std::process::Command;

    /// Check if we're running with sudo
    fn has_sudo() -> bool {
        std::env::var("USER").unwrap_or_default() == "root" ||
        std::env::var("SUDO_USER").is_ok()
    }

    /// Ensure httpjail group exists
    fn ensure_httpjail_group() -> Result<(), String> {
        // Check if group exists
        let check = Command::new("dscl")
            .args(&[".", "-read", "/Groups/httpjail"])
            .output()
            .map_err(|e| format!("Failed to check group: {}", e))?;
        
        if !check.status.success() {
            // Create the group
            println!("Creating httpjail group...");
            let create = Command::new("sudo")
                .args(&["dseditgroup", "-o", "create", "httpjail"])
                .output()
                .map_err(|e| format!("Failed to create group: {}", e))?;
            
            if !create.status.success() {
                return Err(format!("Failed to create httpjail group: {}", 
                    String::from_utf8_lossy(&create.stderr)));
            }
        }
        
        Ok(())
    }

    /// Clean up PF rules
    fn cleanup_pf_rules() {
        let _ = Command::new("sudo")
            .args(&["pfctl", "-a", "httpjail", "-F", "all"])
            .output();
    }

    /// Run httpjail with given arguments
    fn run_httpjail(args: Vec<&str>) -> Result<(i32, String, String), String> {
        // Build the httpjail binary first
        let build = Command::new("cargo")
            .args(&["build", "--bin", "httpjail"])
            .output()
            .map_err(|e| format!("Failed to build: {}", e))?;
        
        if !build.status.success() {
            return Err(format!("Build failed: {}", String::from_utf8_lossy(&build.stderr)));
        }

        // Get the binary path
        let binary_path = "target/debug/httpjail";
        
        // Run with sudo
        let mut cmd = Command::new("sudo");
        cmd.arg("-E") // Preserve environment
           .arg(binary_path);
        
        for arg in args {
            cmd.arg(arg);
        }
        
        let output = cmd.output()
            .map_err(|e| format!("Failed to execute: {}", e))?;
        
        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        
        Ok((exit_code, stdout, stderr))
    }

    #[test]
    #[ignore] // Run with: cargo test -- --ignored
    fn test_jail_setup_and_cleanup() {
        if !has_sudo() {
            eprintln!("This test requires sudo. Run with: sudo -E cargo test -- --ignored");
            return;
        }

        // Ensure group exists
        ensure_httpjail_group().expect("Failed to ensure group");
        
        // Clean up any existing rules first
        cleanup_pf_rules();
        
        // Run a simple command with httpjail
        let result = run_httpjail(vec![
            "-r", "allow: .*",
            "--", "echo", "test"
        ]);
        
        match result {
            Ok((code, stdout, _stderr)) => {
                assert_eq!(code, 0, "Command should succeed");
                assert!(stdout.contains("test"), "Output should contain 'test'");
            }
            Err(e) => panic!("Test failed: {}", e)
        }
        
        // Clean up
        cleanup_pf_rules();
    }

    #[test]
    #[ignore]
    fn test_http_request_allow() {
        if !has_sudo() {
            eprintln!("This test requires sudo. Run with: sudo -E cargo test -- --ignored");
            return;
        }

        ensure_httpjail_group().expect("Failed to ensure group");
        cleanup_pf_rules();
        
        // Test allowing httpbin.org
        let result = run_httpjail(vec![
            "-r", "allow: httpbin\\.org",
            "--", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
            "http://httpbin.org/get"
        ]);
        
        match result {
            Ok((code, stdout, _stderr)) => {
                assert_eq!(code, 0, "curl should succeed");
                assert_eq!(stdout.trim(), "200", "Should get HTTP 200");
            }
            Err(e) => panic!("Test failed: {}", e)
        }
        
        cleanup_pf_rules();
    }

    #[test]
    #[ignore]
    fn test_http_request_deny() {
        if !has_sudo() {
            eprintln!("This test requires sudo. Run with: sudo -E cargo test -- --ignored");
            return;
        }

        ensure_httpjail_group().expect("Failed to ensure group");
        cleanup_pf_rules();
        
        // Test denying example.com while allowing httpbin.org
        let result = run_httpjail(vec![
            "-r", "allow: httpbin\\.org",
            "--", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
            "http://example.com"
        ]);
        
        match result {
            Ok((code, stdout, _stderr)) => {
                assert_eq!(code, 0, "curl should complete");
                assert_eq!(stdout.trim(), "403", "Should get HTTP 403 Forbidden");
            }
            Err(e) => panic!("Test failed: {}", e)
        }
        
        cleanup_pf_rules();
    }

    #[test]
    #[ignore]
    fn test_method_specific_rules() {
        if !has_sudo() {
            eprintln!("This test requires sudo. Run with: sudo -E cargo test -- --ignored");
            return;
        }

        ensure_httpjail_group().expect("Failed to ensure group");
        cleanup_pf_rules();
        
        // Test allowing only GET requests
        let get_result = run_httpjail(vec![
            "-r", "allow-get: httpbin\\.org",
            "--", "curl", "-X", "GET", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
            "http://httpbin.org/get"
        ]);
        
        match get_result {
            Ok((code, stdout, _)) => {
                assert_eq!(code, 0);
                assert_eq!(stdout.trim(), "200", "GET should be allowed");
            }
            Err(e) => panic!("GET test failed: {}", e)
        }
        
        // Test that POST is denied with same rule
        let post_result = run_httpjail(vec![
            "-r", "allow-get: httpbin\\.org",
            "--", "curl", "-X", "POST", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
            "http://httpbin.org/post"
        ]);
        
        match post_result {
            Ok((code, stdout, _)) => {
                assert_eq!(code, 0);
                assert_eq!(stdout.trim(), "403", "POST should be denied");
            }
            Err(e) => panic!("POST test failed: {}", e)
        }
        
        cleanup_pf_rules();
    }

    #[test]
    #[ignore]
    fn test_exit_code_propagation() {
        if !has_sudo() {
            eprintln!("This test requires sudo. Run with: sudo -E cargo test -- --ignored");
            return;
        }

        ensure_httpjail_group().expect("Failed to ensure group");
        cleanup_pf_rules();
        
        // Test that exit codes are propagated
        let result = run_httpjail(vec![
            "-r", "allow: .*",
            "--", "sh", "-c", "exit 42"
        ]);
        
        match result {
            Ok((code, _, _)) => {
                assert_eq!(code, 42, "Exit code should be propagated");
            }
            Err(e) => panic!("Test failed: {}", e)
        }
        
        cleanup_pf_rules();
    }

    #[test]
    #[ignore]
    fn test_log_only_mode() {
        if !has_sudo() {
            eprintln!("This test requires sudo. Run with: sudo -E cargo test -- --ignored");
            return;
        }

        ensure_httpjail_group().expect("Failed to ensure group");
        cleanup_pf_rules();
        
        // In log-only mode, all requests should be allowed
        let result = run_httpjail(vec![
            "--log-only",
            "--", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
            "http://example.com"
        ]);
        
        match result {
            Ok((code, stdout, _)) => {
                assert_eq!(code, 0);
                assert_eq!(stdout.trim(), "200", "Should allow in log-only mode");
            }
            Err(e) => panic!("Test failed: {}", e)
        }
        
        cleanup_pf_rules();
    }

    #[test]
    #[ignore]
    fn test_dry_run_mode() {
        if !has_sudo() {
            eprintln!("This test requires sudo. Run with: sudo -E cargo test -- --ignored");
            return;
        }

        ensure_httpjail_group().expect("Failed to ensure group");
        cleanup_pf_rules();
        
        // In dry-run mode, deny rules should not actually block
        let result = run_httpjail(vec![
            "--dry-run", "-r", "deny: .*",
            "--", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", 
            "http://httpbin.org/get"
        ]);
        
        match result {
            Ok((code, stdout, _)) => {
                assert_eq!(code, 0);
                assert_eq!(stdout.trim(), "200", "Should allow in dry-run mode");
            }
            Err(e) => panic!("Test failed: {}", e)
        }
        
        cleanup_pf_rules();
    }
}

#[cfg(not(target_os = "macos"))]
mod other_platforms {
    #[test]
    fn test_platform_not_supported() {
        println!("Jail integration tests are only supported on macOS");
    }
}