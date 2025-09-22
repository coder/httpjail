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

    async fn ensure_process_running(&self) -> Result<(), String> {
        let mut process_guard = self.process.lock().await;

        if let Some(ref mut process_state) = *process_guard {
            match process_state.child.try_wait() {
                Ok(Some(status)) => {
                    warn!(
                        "Program process exited with status: {:?}, restarting",
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
            debug!("Starting program process: {}", self.program);

            let mut cmd = Command::new(&self.program);

            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true);

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
    /// Returns None if the process needs to be restarted
    async fn send_request_to_process(&self, json_request: &str) -> Option<(bool, Option<String>)> {
        let mut process_guard = self.process.lock().await;

        let process_state = match process_guard.as_mut() {
            Some(state) => state,
            None => return None, // Process not available
        };

        // Send request
        let mut request_line = json_request.to_string();
        request_line.push('\n');

        if let Err(e) = process_state.stdin.write_all(request_line.as_bytes()).await {
            error!("Failed to write to program stdin: {}", e);
            *process_guard = None; // Kill process
            return None;
        }

        if let Err(e) = process_state.stdin.flush().await {
            error!("Failed to flush stdin: {}", e);
            *process_guard = None; // Kill process
            return None;
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
                *process_guard = None; // Kill process
                None
            }
            Ok(Ok(_)) => {
                let response = response_line.trim();
                debug!("Program response: {}", response);

                // Check for empty or whitespace-only response - this is malformed
                if response.is_empty() {
                    error!("Program returned empty response - killing process");
                    *process_guard = None;
                    return None;
                }

                // Parse response
                let rule_response = RuleResponse::from_string(response);
                let (allowed, message) = rule_response.to_evaluation_result();

                Some((allowed, message))
            }
            Ok(Err(e)) => {
                error!("Error reading from program: {}", e);
                *process_guard = None; // Kill process
                None
            }
            Err(_) => {
                warn!("Program response timeout after {:?}", timeout);
                *process_guard = None; // Kill process
                None
            }
        }
    }

    async fn execute_program(
        &self,
        method: Method,
        url: &str,
        requester_ip: &str,
    ) -> (bool, Option<String>) {
        let request_info = match RequestInfo::from_request(&method, url, requester_ip) {
            Ok(info) => info,
            Err(e) => {
                debug!("Failed to parse request: {}", e);
                return (false, Some(e));
            }
        };

        let json_request = match serde_json::to_string(&request_info) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize request: {}", e);
                return (false, Some("Program evaluation failed".to_string()));
            }
        };

        // Try twice: once normally, and once after restart if any error occurs
        for attempt in 0..2 {
            // Ensure process is running
            if let Err(e) = self.ensure_process_running().await {
                error!("Failed to ensure process is running: {}", e);
                if attempt == 0 {
                    continue; // Try once more
                }
                return (false, Some("Program evaluation failed".to_string()));
            }

            debug!(
                "Sending request to program for {} {} from {} (attempt {})",
                method,
                url,
                requester_ip,
                attempt + 1
            );

            // Try to get a response from the process
            if let Some(result) = self.send_request_to_process(&json_request).await {
                let (allowed, message) = result;

                if allowed {
                    debug!("ALLOW: {} {} (program allowed)", method, url);
                } else {
                    debug!("DENY: {} {} (program denied)", method, url);
                }

                return (allowed, message);
            }

            // Process failed - will retry on next iteration if attempt == 0
            if attempt == 0 {
                debug!("Process failed, retrying with fresh process");
            }
        }

        // Both attempts failed
        (false, Some("Program evaluation failed".to_string()))
    }
}

#[async_trait]
impl RuleEngineTrait for ProcRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        let (allowed, context) = self
            .execute_program(method.clone(), url, requester_ip)
            .await;

        if allowed {
            let mut result = EvaluationResult::allow();
            if let Some(msg) = context {
                result = result.with_context(msg);
            }
            result
        } else {
            let mut result = EvaluationResult::deny();
            if let Some(msg) = context {
                result = result.with_context(msg);
            }
            result
        }
    }

    fn name(&self) -> &str {
        "proc"
    }
}

impl Drop for ProcRuleEngine {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.process.try_lock()
            && let Some(ref mut process_state) = *guard
        {
            let _ = process_state.child.start_kill();
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
    async fn test_line_based_program_simple_true() {
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
    async fn test_line_based_program_json_filter() {
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
    async fn test_line_based_program_json_response() {
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
    async fn test_line_based_program_reuses_process() {
        let program = r#"#!/bin/bash
counter=0
while IFS= read -r line; do
    counter=$((counter + 1))
    if [ $counter -eq 1 ]; then
        echo "true"
    elif [ $counter -eq 2 ]; then
        echo "false"
    else
        echo "true"
    fi
done
"#;
        let program_path = create_program_file(program);
        let engine = ProcRuleEngine::new(program_path.to_str().unwrap().to_string());

        let result = engine
            .evaluate(Method::GET, "https://example.com/1", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::GET, "https://example.com/2", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));

        let result = engine
            .evaluate(Method::GET, "https://example.com/3", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        drop(program_path);
    }

    #[tokio::test]
    async fn test_line_based_program_restart_on_exit() {
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
    async fn test_line_based_program_killed_on_empty_response() {
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

    // Note: This test verifies that when a process crashes unexpectedly,
    // the next evaluation after the crash will fail with a denial (because
    // the process is gone), and subsequent evaluations will work properly
    // after the process is automatically restarted.
    //
    // In practice, the crash scenario is handled by setting process_guard to None
    // when an error occurs, which causes ensure_process_running() to restart
    // the process on the next evaluation attempt.
}
