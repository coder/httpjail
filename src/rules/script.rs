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

pub struct ScriptRuleEngine {
    script: String,
    process: Arc<Mutex<Option<ScriptProcess>>>,
}

struct ScriptProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl ScriptRuleEngine {
    pub fn new(script: String) -> Self {
        ScriptRuleEngine {
            script,
            process: Arc::new(Mutex::new(None)),
        }
    }

    async fn ensure_process_running(&self) -> Result<(), String> {
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
            debug!("Starting script process: {}", self.script);

            let mut cmd = if self.script.contains(' ') {
                let mut cmd = Command::new("sh");
                cmd.arg("-c").arg(&self.script);
                cmd
            } else {
                Command::new(&self.script)
            };

            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true);

            let mut child = cmd
                .spawn()
                .map_err(|e| format!("Failed to spawn script: {}", e))?;

            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| "Failed to get stdin handle".to_string())?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| "Failed to get stdout handle".to_string())?;

            *process_guard = Some(ScriptProcess {
                child,
                stdin,
                stdout: BufReader::new(stdout),
            });
        }

        Ok(())
    }

    async fn execute_script(
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
            return (false, Some("Script evaluation failed".to_string()));
        }

        let json_request = match serde_json::to_string(&request_info) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize request: {}", e);
                return (false, Some("Script evaluation failed".to_string()));
            }
        };

        debug!(
            "Sending request to script for {} {} from {}",
            method, url, requester_ip
        );

        let mut process_guard = self.process.lock().await;
        if let Some(ref mut process_state) = *process_guard {
            let mut request_line = json_request;
            request_line.push('\n');

            if let Err(e) = process_state.stdin.write_all(request_line.as_bytes()).await {
                error!("Failed to write to script stdin: {}", e);
                *process_guard = None;
                return (false, Some("Script evaluation failed".to_string()));
            }

            if let Err(e) = process_state.stdin.flush().await {
                error!("Failed to flush stdin: {}", e);
                *process_guard = None;
                return (false, Some("Script evaluation failed".to_string()));
            }

            let timeout = Duration::from_secs(5);
            let mut response_line = String::new();
            match tokio::time::timeout(timeout, process_state.stdout.read_line(&mut response_line))
                .await
            {
                Ok(Ok(0)) => {
                    warn!("Script closed stdout unexpectedly");
                    *process_guard = None;
                    (false, Some("Script closed unexpectedly".to_string()))
                }
                Ok(Ok(_)) => {
                    let response = response_line.trim();
                    debug!("Script response: {}", response);

                    match response {
                        "true" => {
                            debug!("ALLOW: {} {} (script allowed)", method, url);
                            (true, None)
                        }
                        "false" => {
                            debug!("DENY: {} {} (script denied)", method, url);
                            (false, None)
                        }
                        _ => {
                            // Try to parse as JSON first
                            if let Ok(json_response) =
                                serde_json::from_str::<serde_json::Value>(response)
                            {
                                let allowed = json_response
                                    .get("allow")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);

                                let message = json_response
                                    .get("message")
                                    .and_then(|v| v.as_str())
                                    .map(String::from);

                                if allowed {
                                    debug!("ALLOW: {} {} (script allowed via JSON)", method, url);
                                } else {
                                    debug!("DENY: {} {} (script denied via JSON)", method, url);
                                }

                                (allowed, message)
                            } else {
                                // Not JSON, treat the output as a deny message
                                debug!("DENY: {} {} (script returned: {})", method, url, response);
                                (false, Some(response.to_string()))
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Error reading from script: {}", e);
                    *process_guard = None;
                    (false, Some("Script evaluation failed".to_string()))
                }
                Err(_) => {
                    warn!("Script response timeout after {:?}", timeout);
                    *process_guard = None;
                    (false, Some("Script response timeout".to_string()))
                }
            }
        } else {
            (false, Some("Script process not available".to_string()))
        }
    }
}

#[async_trait]
impl RuleEngineTrait for ScriptRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        let (allowed, context) = self.execute_script(method.clone(), url, requester_ip).await;

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
        "script"
    }
}

impl Drop for ScriptRuleEngine {
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
    async fn test_line_based_script_simple_true() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/bash
while IFS= read -r line; do
    echo "true"
done
"#;
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

        let engine = ScriptRuleEngine::new(script_path.to_str().unwrap().to_string());

        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::POST, "https://github.com/api", "192.168.1.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        drop(script_path);
    }

    #[tokio::test]
    async fn test_line_based_script_json_filter() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/usr/bin/env python3
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

        let engine = ScriptRuleEngine::new(script_path.to_str().unwrap().to_string());

        let result = engine
            .evaluate(Method::GET, "https://github.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));

        drop(script_path);
    }

    #[tokio::test]
    async fn test_line_based_script_json_response() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    try:
        request = json.loads(line)
        if 'blocked' in request.get('host', ''):
            response = {'allow': False, 'message': f"Host {request['host']} is blocked"}
        else:
            response = {'allow': True}
        print(json.dumps(response))
        sys.stdout.flush()
    except Exception as e:
        print(json.dumps({'allow': False, 'message': str(e)}))
        sys.stdout.flush()
"#;
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

        let engine = ScriptRuleEngine::new(script_path.to_str().unwrap().to_string());

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

        drop(script_path);
    }

    #[tokio::test]
    async fn test_line_based_script_reuses_process() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/bash
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

        let engine = ScriptRuleEngine::new(script_path.to_str().unwrap().to_string());

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

        drop(script_path);
    }
}
