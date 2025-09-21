use super::{EvaluationResult, RuleEngineTrait};
use async_trait::async_trait;
use hyper::Method;
use std::time::Duration;
use tracing::debug;
use url::Url;

#[derive(Clone)]
pub struct ShellRuleEngine {
    script: String,
}

impl ShellRuleEngine {
    pub fn new(script: String) -> Self {
        ShellRuleEngine { script }
    }

    async fn execute_script(
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
            .kill_on_drop(true); // Ensure child is killed if dropped

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
                // Timeout elapsed - process will be killed automatically due to kill_on_drop
                debug!("Script execution timed out after {:?}", timeout);
                (false, "Script execution timed out".to_string())
            }
        }
    }
}

#[async_trait]
impl RuleEngineTrait for ShellRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        let (allowed, context) = self.execute_script(method.clone(), url, requester_ip).await;

        if allowed {
            debug!("ALLOW: {} {} (script allowed)", method, url);
            let mut result = EvaluationResult::allow();
            if !context.is_empty() {
                result = result.with_context(context);
            }
            result
        } else {
            debug!("DENY: {} {} (script denied)", method, url);
            let mut result = EvaluationResult::deny();
            if !context.is_empty() {
                result = result.with_context(context);
            }
            result
        }
    }

    fn name(&self) -> &str {
        "shell"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Action;
    use std::fs;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_script_allow() {
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

        let engine = ShellRuleEngine::new(script_path.to_str().unwrap().to_string());
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;

        assert!(matches!(result.action, Action::Allow));
        drop(script_path);
    }

    #[tokio::test]
    async fn test_script_deny() {
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

        let engine = ShellRuleEngine::new(script_path.to_str().unwrap().to_string());
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;

        assert!(matches!(result.action, Action::Deny));
        drop(script_path);
    }

    #[tokio::test]
    async fn test_script_with_context() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/sh
echo "Blocked by policy"
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

        let engine = ShellRuleEngine::new(script_path.to_str().unwrap().to_string());
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;

        assert!(matches!(result.action, Action::Deny));
        assert_eq!(result.context, Some("Blocked by policy".to_string()));
        drop(script_path);
    }
}
