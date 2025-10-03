use super::common::{RequestInfo, RuleResponse};
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

pub struct ProcRuleEngine {
    program: String,
    process: Arc<Mutex<Option<ProcessState>>>,
}

/// State for a running process
/// When dropped, the child process is automatically killed due to kill_on_drop(true)
struct ProcessState {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl ProcRuleEngine {
    pub fn new(program: String) -> Self {
        ProcRuleEngine {
            program,
            process: Arc::new(Mutex::new(None)),
        }
    }

    /// Explicitly kill a process by taking ownership and dropping it
    /// This is more self-documenting than relying on implicit drops
    #[inline]
    fn kill_process(process_state: ProcessState) {
        // The process is killed when ProcessState is dropped due to kill_on_drop(true)
        drop(process_state);
    }

    /// Ensure a process is running, restarting if necessary
    /// Takes a mutable reference to the guard to avoid multiple lock acquisitions
    async fn ensure_process_running(
        &self,
        process_guard: &mut Option<ProcessState>,
    ) -> Result<(), String> {
        // Check if existing process is still alive
        if let Some(mut process_state) = process_guard.take() {
            match process_state.child.try_wait() {
                Ok(Some(status)) => {
                    warn!(
                        "Program process exited with status: {:?}, restarting",
                        status
                    );
                    Self::kill_process(process_state);
                }
                Ok(None) => {
                    // Process is still running, put it back
                    *process_guard = Some(process_state);
                    return Ok(());
                }
                Err(e) => {
                    error!("Failed to check process status: {}, restarting", e);
                    Self::kill_process(process_state);
                }
            }
        }

        // Start new process if needed
        if process_guard.is_none() {
            debug!("Starting program process: {}", self.program);

            let mut cmd = Command::new(&self.program);
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true); // Ensures process is killed when Child is dropped

            let mut child = cmd
                .spawn()
                .map_err(|e| format!("Failed to spawn program: {}", e))?;

            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| "Failed to get stdin handle".to_string())?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| "Failed to get stdout handle".to_string())?;

            *process_guard = Some(ProcessState {
                child,
                stdin,
                stdout: BufReader::new(stdout),
            });
        }

        Ok(())
    }

    /// Send a request to the program and get a response
    /// Returns Err if the process needs to be restarted
    async fn send_request_to_process(
        &self,
        process_guard: &mut Option<ProcessState>,
        json_request: &str,
    ) -> Result<(bool, Option<String>, Option<u64>), String> {
        // Ensure we have a running process
        self.ensure_process_running(process_guard).await?;

        let process_state = process_guard
            .as_mut()
            .ok_or_else(|| "Process not available after ensure_process_running".to_string())?;

        // Send request
        let mut request_line = json_request.to_string();
        request_line.push('\n');

        if let Err(e) = process_state.stdin.write_all(request_line.as_bytes()).await {
            error!("Failed to write to program stdin: {}", e);
            if let Some(state) = process_guard.take() {
                Self::kill_process(state);
            }
            return Err("Failed to write to program".to_string());
        }

        if let Err(e) = process_state.stdin.flush().await {
            error!("Failed to flush stdin: {}", e);
            if let Some(state) = process_guard.take() {
                Self::kill_process(state);
            }
            return Err("Failed to flush stdin".to_string());
        }

        // Read response with timeout
        let timeout = Duration::from_secs(5);
        let mut response_line = String::new();

        match tokio::time::timeout(timeout, process_state.stdout.read_line(&mut response_line))
            .await
        {
            Ok(Ok(0)) => {
                // EOF - process exited
                warn!("Program closed stdout unexpectedly");
                if let Some(state) = process_guard.take() {
                    Self::kill_process(state);
                }
                Err("Program closed unexpectedly".to_string())
            }
            Ok(Ok(_)) => {
                let response = response_line.trim();
                debug!("Program response: {}", response);

                // Check for empty or whitespace-only response - this is malformed
                if response.is_empty() {
                    error!("Program returned empty response - killing process");
                    if let Some(state) = process_guard.take() {
                        Self::kill_process(state);
                    }
                    return Err("Program returned empty response".to_string());
                }

                // Parse response
                let rule_response = RuleResponse::from_string(response);
                let (allowed, message, max_tx_bytes) = rule_response.to_evaluation_result();

                Ok((allowed, message, max_tx_bytes))
            }
            Ok(Err(e)) => {
                error!("Error reading from program: {}", e);
                if let Some(state) = process_guard.take() {
                    Self::kill_process(state);
                }
                Err(format!("Error reading from program: {}", e))
            }
            Err(_) => {
                warn!("Program response timeout after {:?}", timeout);
                if let Some(state) = process_guard.take() {
                    Self::kill_process(state);
                }
                Err("Program response timeout".to_string())
            }
        }
    }

    async fn execute_program(
        &self,
        method: Method,
        url: &str,
        requester_ip: &str,
    ) -> EvaluationResult {
        let request_info = match RequestInfo::from_request(&method, url, requester_ip) {
            Ok(info) => info,
            Err(e) => {
                debug!("Failed to parse request: {}", e);
                return EvaluationResult::deny().with_context(e);
            }
        };

        let json_request = match serde_json::to_string(&request_info) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize request: {}", e);
                return EvaluationResult::deny()
                    .with_context("Program evaluation failed".to_string());
            }
        };

        let mut process_guard = self.process.lock().await;

        // Try twice: once normally, and once after restart if any error occurs
        for attempt in 0..2 {
            debug!(
                "Sending request to program for {} {} from {} (attempt {})",
                method,
                url,
                requester_ip,
                attempt + 1
            );

            // Try to get a response from the process
            match self
                .send_request_to_process(&mut process_guard, &json_request)
                .await
            {
                Ok((allowed, message, max_tx_bytes)) => {
                    if allowed {
                        debug!("ALLOW: {} {} (program allowed)", method, url);
                        let mut result = EvaluationResult::allow();
                        if let Some(msg) = message {
                            result = result.with_context(msg);
                        }
                        if let Some(bytes) = max_tx_bytes {
                            result = result.with_max_tx_bytes(bytes);
                        }
                        return result;
                    } else {
                        debug!("DENY: {} {} (program denied)", method, url);
                        return match message {
                            Some(msg) => EvaluationResult::deny().with_context(msg),
                            None => EvaluationResult::deny(),
                        };
                    }
                }
                Err(e) => {
                    debug!("Request failed: {}", e);
                    if attempt == 0 {
                        debug!("Retrying with fresh process");
                        // Process will be restarted on next iteration by send_request_to_process
                    }
                }
            }
        }

        // Both attempts failed
        EvaluationResult::deny().with_context("Program evaluation failed".to_string())
    }
}

#[async_trait]
impl RuleEngineTrait for ProcRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        self.execute_program(method, url, requester_ip).await
    }

    fn name(&self) -> &str {
        "proc"
    }
}

impl Drop for ProcRuleEngine {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.process.try_lock() {
            if let Some(process_state) = guard.take() {
                // Explicitly kill the process on drop
                Self::kill_process(process_state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Action;
    use std::fs;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempPath};

    /// Helper function to create an executable program file with the given content
    fn create_program_file(content: &str) -> TempPath {
        let mut program_file = NamedTempFile::new().unwrap();
        program_file.write_all(content.as_bytes()).unwrap();
        program_file.flush().unwrap();

        let program_path = program_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&program_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&program_path, perms).unwrap();
        }

        program_path
    }

    #[tokio::test]
    async fn test_simple_allow() {
        let program = r#"#!/bin/bash
while IFS= read -r line; do
    echo "true"
done
"#;
        let program_path = create_program_file(program);
        let engine = ProcRuleEngine::new(program_path.to_str().unwrap().to_string());

        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::POST, "https://github.com/api", "192.168.1.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        drop(program_path);
    }

    #[tokio::test]
    async fn test_json_filter() {
        let program = r#"#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    try:
        request = json.loads(line)
        if request.get('host') == 'github.com':
            print('true')
        else:
            print('false')
        sys.stdout.flush()
    except:
        print('false')
        sys.stdout.flush()
"#;
        let program_path = create_program_file(program);
        let engine = ProcRuleEngine::new(program_path.to_str().unwrap().to_string());

        let result = engine
            .evaluate(Method::GET, "https://github.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));

        drop(program_path);
    }

    #[tokio::test]
    async fn test_json_response() {
        let program = r#"#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    try:
        request = json.loads(line)
        if 'blocked' in request.get('host', ''):
            response = {'allow': False, 'deny_message': f"Host {request['host']} is blocked"}
        else:
            response = {'allow': True}
        print(json.dumps(response))
        sys.stdout.flush()
    except Exception as e:
        print(json.dumps({'allow': False, 'deny_message': str(e)}))
        sys.stdout.flush()
"#;
        let program_path = create_program_file(program);
        let engine = ProcRuleEngine::new(program_path.to_str().unwrap().to_string());

        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));
        assert_eq!(result.context, None);

        let result = engine
            .evaluate(Method::GET, "https://blocked.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
        assert_eq!(
            result.context,
            Some("Host blocked.com is blocked".to_string())
        );

        drop(program_path);
    }

    #[tokio::test]
    async fn test_restart_on_exit() {
        // Program that exits after every request
        let program = r#"#!/usr/bin/env python3
import json
import sys

# Read exactly one line, respond, then exit
line = sys.stdin.readline()
request = json.loads(line.strip())

# Simple response to verify process restart works
response = {"allow": True, "deny_message": f"Handled {request['path']}"}
print(json.dumps(response))
sys.stdout.flush()
sys.exit(0)  # Always exit after handling one request
"#;
        let program_path = create_program_file(program);
        let engine = ProcRuleEngine::new(program_path.to_str().unwrap().to_string());

        // First request - process starts, responds, and exits
        let result = engine
            .evaluate(Method::GET, "https://example.com/1", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        // Second request - verifies that after process exit, a new process is started
        // automatically without any delay or error
        let result = engine
            .evaluate(Method::GET, "https://example.com/2", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        // Both requests should succeed, proving that process restart is seamless
        drop(program_path);
    }

    #[tokio::test]
    async fn test_stateful_process() {
        // Test that process stays alive and maintains state across multiple requests
        // Each request N only allows domain N.com
        let program = r#"#!/usr/bin/env python3
import json
import sys

request_count = 0
for line in sys.stdin:
    request_count += 1
    request = json.loads(line.strip())
    
    # Only allow requests to {request_count}.com
    expected_host = f"{request_count}.com"
    if request['host'] == expected_host:
        response = {"allow": True}
    else:
        response = {"allow": False, "deny_message": f"Request {request_count}: Expected {expected_host}, got {request['host']}"}
    
    print(json.dumps(response))
    sys.stdout.flush()
"#;
        let program_path = create_program_file(program);
        let engine = ProcRuleEngine::new(program_path.to_str().unwrap().to_string());

        // Make 10 iterations testing sequential numbering
        let mut total_requests = 0;
        for _ in 1..=10 {
            // Test allowed domain - each request N only allows N.com
            total_requests += 1;
            let allowed_url = format!("https://{}.com/test", total_requests);
            let result = engine
                .evaluate(Method::GET, &allowed_url, "127.0.0.1")
                .await;
            assert!(
                matches!(result.action, Action::Allow),
                "Request {} to {}.com should be allowed",
                total_requests,
                total_requests
            );

            // Test denied domain - wrong number should be denied
            total_requests += 1;
            let denied_url = "https://wrong.com/test";
            let result = engine.evaluate(Method::GET, denied_url, "127.0.0.1").await;
            assert!(
                matches!(result.action, Action::Deny),
                "Request {} to wrong.com should be denied",
                total_requests
            );
            assert!(
                result
                    .context
                    .as_ref()
                    .is_some_and(|msg| msg.contains(&format!("Request {}", total_requests))),
                "Deny message should indicate this is request {} in the process",
                total_requests
            );
        }

        // Final test: verify the process is still using the same instance
        // After 20 requests (10 iterations * 2), request 21 should only allow 21.com
        let result = engine
            .evaluate(Method::GET, "https://21.com/test", "127.0.0.1")
            .await;
        assert!(
            matches!(result.action, Action::Allow),
            "Request 21 to 21.com should be allowed"
        );

        // Request 22 should expect 22.com
        let result = engine
            .evaluate(Method::GET, "https://1.com/test", "127.0.0.1")
            .await;
        assert!(
            matches!(result.action, Action::Deny),
            "Request 22 should deny 1.com (expecting 22.com)"
        );
        assert!(
            result
                .context
                .as_ref()
                .is_some_and(|msg| msg.contains("Request 22")),
            "Should indicate this is request 22 in the process lifecycle"
        );

        drop(program_path);
    }

    #[tokio::test]
    async fn test_killed_on_empty_response() {
        // Program that returns empty response on second request
        let program = r#"#!/usr/bin/env python3
import sys
counter = 0
for line in sys.stdin:
    counter += 1
    if counter == 1:
        print('true')
    elif counter == 2:
        print('')  # Empty response - should cause process to be killed
    else:
        print('false')  # After restart
    sys.stdout.flush()
"#;
        let program_path = create_program_file(program);
        let engine = ProcRuleEngine::new(program_path.to_str().unwrap().to_string());

        // First request - should work
        let result = engine
            .evaluate(Method::GET, "https://example.com/1", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        // Second request - empty response should kill process and retry succeeds
        let result = engine
            .evaluate(Method::GET, "https://example.com/2", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow)); // Retry gets 'true' from fresh process

        // Third request - should be second request in new process (which returns empty)
        // Then retries and gets 'true' from yet another fresh process
        let result = engine
            .evaluate(Method::GET, "https://example.com/3", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow)); // Gets empty, retries, gets 'true' from fresh

        drop(program_path);
    }
}
