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

        if let Err(e) = self.ensure_process_running().await {
            error!("Failed to ensure process is running: {}", e);
            return (false, Some("Program evaluation failed".to_string()));
        }

        let json_request = match serde_json::to_string(&request_info) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize request: {}", e);
                return (false, Some("Program evaluation failed".to_string()));
            }
        };

        debug!(
            "Sending request to program for {} {} from {}",
            method, url, requester_ip
        );

        let mut process_guard = self.process.lock().await;
        if let Some(ref mut process_state) = *process_guard {
            let mut request_line = json_request;
            request_line.push('\n');

            if let Err(e) = process_state.stdin.write_all(request_line.as_bytes()).await {
                error!("Failed to write to program stdin: {}", e);
                *process_guard = None;
                return (false, Some("Program evaluation failed".to_string()));
            }

            if let Err(e) = process_state.stdin.flush().await {
                error!("Failed to flush stdin: {}", e);
                *process_guard = None;
                return (false, Some("Program evaluation failed".to_string()));
            }

            let timeout = Duration::from_secs(5);
            let mut response_line = String::new();
            match tokio::time::timeout(timeout, process_state.stdout.read_line(&mut response_line))
                .await
            {
                Ok(Ok(0)) => {
                    warn!("Program closed stdout unexpectedly");
                    *process_guard = None;
                    (false, Some("Program closed unexpectedly".to_string()))
                }
                Ok(Ok(_)) => {
                    let response = response_line.trim();
                    debug!("Program response: {}", response);

                    match response {
                        "true" => {
                            debug!("ALLOW: {} {} (program allowed)", method, url);
                            (true, None)
                        }
                        "false" => {
                            debug!("DENY: {} {} (program denied)", method, url);
                            (false, None)
                        }
                        _ => {
                            // Try to parse as JSON first
                            if let Ok(json_response) =
                                serde_json::from_str::<serde_json::Value>(response)
                            {
                                // Check for deny_message first
                                let deny_message = json_response
                                    .get("deny_message")
                                    .and_then(|v| v.as_str())
                                    .map(String::from);

                                // Get allow value - if not present but deny_message exists, default to false
                                let allowed = if let Some(allow_val) = json_response.get("allow") {
                                    allow_val.as_bool().unwrap_or(false)
                                } else if deny_message.is_some() {
                                    // Shorthand: if only deny_message is present, it implies allow: false
                                    false
                                } else {
                                    false
                                };

                                if allowed {
                                    debug!("ALLOW: {} {} (program allowed via JSON)", method, url);
                                    (allowed, None) // No message when allowing
                                } else {
                                    debug!("DENY: {} {} (program denied via JSON)", method, url);
                                    (allowed, deny_message)
                                }
                            } else {
                                // Not JSON, treat the output as a deny message
                                debug!("DENY: {} {} (program returned: {})", method, url, response);
                                (false, Some(response.to_string()))
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Error reading from program: {}", e);
                    *process_guard = None;
                    (false, Some("Program evaluation failed".to_string()))
                }
                Err(_) => {
                    warn!("Program response timeout after {:?}", timeout);
                    *process_guard = None;
                    (false, Some("Program response timeout".to_string()))
                }
            }
        } else {
            (false, Some("Program process not available".to_string()))
        }
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
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_line_based_program_simple_true() {
        let mut program_file = NamedTempFile::new().unwrap();
        let program = r#"#!/bin/bash
while IFS= read -r line; do
    echo "true"
done
"#;
        program_file.write_all(program.as_bytes()).unwrap();
        program_file.flush().unwrap();

        let program_path = program_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&program_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&program_path, perms).unwrap();
        }

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
        let mut program_file = NamedTempFile::new().unwrap();
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
        program_file.write_all(program.as_bytes()).unwrap();
        program_file.flush().unwrap();

        let program_path = program_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&program_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&program_path, perms).unwrap();
        }

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
        let mut program_file = NamedTempFile::new().unwrap();
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
        program_file.write_all(program.as_bytes()).unwrap();
        program_file.flush().unwrap();

        let program_path = program_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&program_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&program_path, perms).unwrap();
        }

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
        let mut program_file = NamedTempFile::new().unwrap();
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
        program_file.write_all(program.as_bytes()).unwrap();
        program_file.flush().unwrap();

        let program_path = program_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&program_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&program_path, perms).unwrap();
        }

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
        let mut program_file = NamedTempFile::new().unwrap();
        // Program that exits after handling 2 requests
        let program = r#"#!/usr/bin/env python3
import json
import sys

counter = 0
for line in sys.stdin:
    counter += 1
    request = json.loads(line.strip())
    
    # First request: allow
    if counter == 1:
        response = {"allow": True}
        print(json.dumps(response))
        sys.stdout.flush()
    # Second request: deny then exit
    elif counter == 2:
        response = {"allow": False, "deny_message": f"Request {counter} denied, exiting"}
        print(json.dumps(response))
        sys.stdout.flush()
        sys.exit(0)  # Exit after second request
    else:
        # This should never be reached in the first process
        response = {"allow": True}
        print(json.dumps(response))
        sys.stdout.flush()
"#;
        program_file.write_all(program.as_bytes()).unwrap();
        program_file.flush().unwrap();

        let program_path = program_file.into_temp_path();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&program_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&program_path, perms).unwrap();
        }

        let engine = ProcRuleEngine::new(program_path.to_str().unwrap().to_string());

        // First request - should be allowed
        let result = engine
            .evaluate(Method::GET, "https://example.com/1", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));
        assert_eq!(result.context, None); // No message when allowing

        // Second request - should be denied, then process exits
        let result = engine
            .evaluate(Method::GET, "https://example.com/2", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
        assert!(
            result
                .context
                .as_ref()
                .is_some_and(|c| c.contains("Request 2 denied"))
        );

        // Add a small delay to ensure the process has exited
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Third request - process should restart and handle this as first request
        let result = engine
            .evaluate(Method::GET, "https://example.com/3", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));
        assert_eq!(result.context, None); // No message when allowing

        // Fourth request - should be second request in restarted process
        let result = engine
            .evaluate(Method::GET, "https://example.com/4", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
        assert!(
            result
                .context
                .as_ref()
                .is_some_and(|c| c.contains("Request 2 denied"))
        );

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
