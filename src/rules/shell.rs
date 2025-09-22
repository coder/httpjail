use super::common::RequestInfo;
use super::{EvaluationResult, RuleEngineTrait};
use async_trait::async_trait;
use hyper::Method;
use serde_json;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tracing::{debug, error, warn};
use url::Url;

#[derive(Clone)]
pub struct ShellRuleEngine {
    script: String,
    line_mode: bool,
    // Only used in line mode
    process: Arc<Mutex<Option<LineProcess>>>,
}

struct LineProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl ShellRuleEngine {
    pub fn new(script: String, line_mode: bool) -> Self {
        ShellRuleEngine {
            script,
            line_mode,
            process: Arc::new(Mutex::new(None)),
        }
    }

    // ========== Line-based mode implementation ==========

    async fn ensure_line_process_running(&self) -> Result<(), String> {
        let mut process_guard = self.process.lock().await;

        if let Some(ref mut process_state) = *process_guard {
            match process_state.child.try_wait() {
                Ok(Some(status)) => {
                    warn!(
                        "Script process exited with status: {:?}, restarting",
                        status
                    );
                    *process_guard = None;
                }
                Ok(None) => {
                    return Ok(());
                }
                Err(e) => {
                    error!("Failed to check process status: {}, restarting", e);
                    *process_guard = None;
                }
            }
        }

        if process_guard.is_none() {
            debug!("Starting new script process: {}", self.script);

            let mut cmd = if self.script.contains(' ') {
                let mut cmd = Command::new("sh");
                cmd.arg("-c").arg(&self.script);
                cmd
            } else {
                Command::new(&self.script)
            };

            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);

            let mut child = cmd
                .spawn()
                .map_err(|e| format!("Failed to spawn script process: {}", e))?;

            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| "Failed to get stdin handle".to_string())?;

            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| "Failed to get stdout handle".to_string())?;

            *process_guard = Some(LineProcess {
                child,
                stdin,
                stdout: BufReader::new(stdout),
            });

            debug!("Script process started successfully");
        }

        Ok(())
    }

    async fn execute_line_script(
        &self,
        method: Method,
        url: &str,
        requester_ip: &str,
    ) -> (bool, String) {
        if let Err(e) = self.ensure_line_process_running().await {
            error!("Failed to ensure script process is running: {}", e);
            return (false, "Script evaluation failed".to_string());
        }

        let request_info = match RequestInfo::from_request(&method, url, requester_ip) {
            Ok(info) => info,
            Err(e) => {
                debug!("Failed to parse request info: {}", e);
                return (false, format!("Failed to parse URL: {}", e));
            }
        };

        let request_line = match serde_json::to_string(&request_info) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize request info: {}", e);
                return (false, "Script evaluation failed".to_string());
            }
        };

        debug!("Sending request to script: {} {} (line mode)", method, url);

        let mut process_guard = self.process.lock().await;
        let process_state = match process_guard.as_mut() {
            Some(state) => state,
            None => {
                error!("Script process not available");
                return (false, "Script evaluation failed".to_string());
            }
        };

        // Send request
        if let Err(e) = process_state.stdin.write_all(request_line.as_bytes()).await {
            error!("Failed to write to script stdin: {}", e);
            *process_guard = None;
            return (false, "Script evaluation failed".to_string());
        }

        if let Err(e) = process_state.stdin.write_all(b"\n").await {
            error!("Failed to write newline to script stdin: {}", e);
            *process_guard = None;
            return (false, "Script evaluation failed".to_string());
        }

        if let Err(e) = process_state.stdin.flush().await {
            error!("Failed to flush script stdin: {}", e);
            *process_guard = None;
            return (false, "Script evaluation failed".to_string());
        }

        // Read response with timeout
        let timeout = Duration::from_secs(30);
        let mut response_line = String::new();

        match tokio::time::timeout(timeout, process_state.stdout.read_line(&mut response_line))
            .await
        {
            Ok(Ok(0)) => {
                warn!("Script stdout closed unexpectedly");
                *process_guard = None;
                (false, "Script evaluation failed".to_string())
            }
            Ok(Ok(_)) => {
                let response = response_line.trim();
                debug!("Script response: {}", response);

                // Try parsing as JSON first
                if let Ok(json_response) = serde_json::from_str::<serde_json::Value>(response) {
                    if let Some(allow) = json_response.get("allow").and_then(|v| v.as_bool()) {
                        let message = json_response
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        debug!(
                            "Script returned {} for {} {} (JSON response)",
                            if allow { "ALLOW" } else { "DENY" },
                            method,
                            url
                        );

                        return (allow, message);
                    }
                }

                // Handle simple string responses
                match response {
                    "true" => {
                        debug!("Script returned ALLOW for {} {}", method, url);
                        (true, String::new())
                    }
                    "false" => {
                        debug!("Script returned DENY for {} {}", method, url);
                        (false, String::new())
                    }
                    other => {
                        debug!("Script returned DENY for {} {} with message", method, url);
                        (false, other.to_string())
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Failed to read from script stdout: {}", e);
                *process_guard = None;
                (false, "Script evaluation failed".to_string())
            }
            Err(_) => {
                error!("Script execution timed out after {:?}", timeout);
                *process_guard = None;
                (false, "Script evaluation failed".to_string())
            }
        }
    }

    // ========== Process-per-request mode implementation ==========

    async fn execute_process_script(
        &self,
        method: Method,
        url: &str,
        requester_ip: &str,
    ) -> (bool, String) {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                debug!("Failed to parse URL '{}': {}", url, e);
                return (false, format!("Failed to parse URL: {}", e));
            }
        };

        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().unwrap_or("");
        let path = parsed_url.path();

        debug!(
            "Executing script for {} {} (host: {}, path: {})",
            method, url, host, path
        );

        // Build the command
        let mut cmd = if self.script.contains(' ') {
            let mut cmd = tokio::process::Command::new("sh");
            cmd.arg("-c").arg(&self.script);
            cmd
        } else {
            tokio::process::Command::new(&self.script)
        };

        cmd.env("HTTPJAIL_URL", url)
            .env("HTTPJAIL_METHOD", method.as_str())
            .env("HTTPJAIL_SCHEME", scheme)
            .env("HTTPJAIL_HOST", host)
            .env("HTTPJAIL_PATH", path)
            .env("HTTPJAIL_REQUESTER_IP", requester_ip)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        // Spawn the child process
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                debug!("Failed to spawn script: {}", e);
                return (false, format!("Script execution failed: {}", e));
            }
        };

        // Wait for completion with timeout
        let timeout = Duration::from_secs(30);
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

                if !stderr.is_empty() {
                    debug!("Script stderr: {}", stderr);
                }

                let allowed = output.status.success();

                debug!(
                    "Script returned {} for {} {} (exit code: {:?})",
                    if allowed { "ALLOW" } else { "DENY" },
                    method,
                    url,
                    output.status.code()
                );

                (allowed, stdout)
            }
            Ok(Err(e)) => {
                debug!("Error waiting for script: {}", e);
                (false, format!("Script execution error: {}", e))
            }
            Err(_) => {
                debug!("Script execution timed out after {:?}", timeout);
                (false, "Script execution timed out".to_string())
            }
        }
    }
}

#[async_trait]
impl RuleEngineTrait for ShellRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        let (allowed, context) = if self.line_mode {
            self.execute_line_script(method.clone(), url, requester_ip)
                .await
        } else {
            self.execute_process_script(method.clone(), url, requester_ip)
                .await
        };

        if allowed {
            debug!("ALLOW: {} {} (shell script allowed)", method, url);
            let mut result = EvaluationResult::allow();
            if !context.is_empty() {
                result = result.with_context(context);
            }
            result
        } else {
            debug!("DENY: {} {} (shell script denied)", method, url);
            let mut result = EvaluationResult::deny();
            if !context.is_empty() {
                result = result.with_context(context);
            }
            result
        }
    }

    fn name(&self) -> &str {
        if self.line_mode {
            "shell-line"
        } else {
            "shell"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Action;
    use std::fs;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_process_mode_allow() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/sh
exit 0
"#;
        use std::io::Write;
        script_file.write_all(script.as_bytes()).unwrap();
        script_file.flush().unwrap();

        let script_path = script_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let engine = ShellRuleEngine::new(script_path.to_str().unwrap().to_string(), false);
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;

        assert!(matches!(result.action, Action::Allow));
        drop(script_path);
    }

    #[tokio::test]
    async fn test_process_mode_deny() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/sh
exit 1
"#;
        use std::io::Write;
        script_file.write_all(script.as_bytes()).unwrap();
        script_file.flush().unwrap();

        let script_path = script_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let engine = ShellRuleEngine::new(script_path.to_str().unwrap().to_string(), false);
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;

        assert!(matches!(result.action, Action::Deny));
        drop(script_path);
    }

    #[tokio::test]
    async fn test_line_mode_simple_true() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/usr/bin/env python3
import sys
while True:
    line = sys.stdin.readline()
    if not line:
        break
    print("true")
    sys.stdout.flush()
"#;
        use std::io::Write;
        script_file.write_all(script.as_bytes()).unwrap();
        script_file.flush().unwrap();

        let script_path = script_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let engine = ShellRuleEngine::new(script_path.to_str().unwrap().to_string(), true);
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;

        assert!(matches!(result.action, Action::Allow));
        drop(script_path);
    }

    #[tokio::test]
    async fn test_line_mode_json_response() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/usr/bin/env python3
import sys
import json
while True:
    line = sys.stdin.readline()
    if not line:
        break
    print(json.dumps({"allow": False, "message": "Test denial"}))
    sys.stdout.flush()
"#;
        use std::io::Write;
        script_file.write_all(script.as_bytes()).unwrap();
        script_file.flush().unwrap();

        let script_path = script_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&script_path, perms).unwrap();
        }

        let engine = ShellRuleEngine::new(script_path.to_str().unwrap().to_string(), true);
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;

        assert!(matches!(result.action, Action::Deny));
        assert_eq!(result.context, Some("Test denial".to_string()));
        drop(script_path);
    }
}
