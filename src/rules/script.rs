use super::{EvaluationResult, RuleEngineTrait};
use hyper::Method;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

#[derive(Clone)]
pub struct ScriptRuleEngine {
    script: String,
}

impl ScriptRuleEngine {
    pub fn new(script: String) -> Self {
        ScriptRuleEngine { script }
    }

    async fn execute_script(&self, method: Method, url: &str) -> (bool, String) {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                warn!("Failed to parse URL '{}': {}", url, e);
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

        // Use tokio runtime to execute async command with timeout
        let script_clone = self.script.clone();
        let method_str = method.as_str().to_string();
        let url_str = url.to_string();
        let scheme_str = scheme.to_string();
        let host_str = host.to_string();
        let path_str = path.to_string();

        // Use spawn_blocking to avoid blocking the async runtime
        let result = tokio::task::spawn_blocking(move || {
            use std::process::{Command, Stdio};
            use std::time::Instant;

            let start = Instant::now();
            let timeout = Duration::from_secs(5);

            let mut cmd = if script_clone.contains(' ') {
                let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
                let mut cmd = Command::new(&shell);
                cmd.arg("-c").arg(&script_clone);
                cmd
            } else {
                Command::new(&script_clone)
            };

            let mut child = match cmd
                .env("HTTPJAIL_URL", &url_str)
                .env("HTTPJAIL_METHOD", &method_str)
                .env("HTTPJAIL_SCHEME", &scheme_str)
                .env("HTTPJAIL_HOST", &host_str)
                .env("HTTPJAIL_PATH", &path_str)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(child) => child,
                Err(e) => {
                    warn!("Failed to spawn script: {}", e);
                    return (false, format!("Script execution failed: {}", e));
                }
            };

            // Poll for completion with timeout
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        // Process has exited
                        let output = child.wait_with_output().unwrap_or_else(|e| {
                            warn!("Failed to read script output: {}", e);
                            std::process::Output {
                                status,
                                stdout: Vec::new(),
                                stderr: Vec::new(),
                            }
                        });

                        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

                        if !stderr.is_empty() {
                            debug!("Script stderr: {}", stderr);
                        }

                        let allowed = status.success();

                        debug!(
                            "Script returned {} for {} {} (exit code: {:?})",
                            if allowed { "ALLOW" } else { "DENY" },
                            method_str,
                            url_str,
                            status.code()
                        );

                        return (allowed, stdout);
                    }
                    Ok(None) => {
                        // Still running
                        if start.elapsed() > timeout {
                            // Timeout - kill the process
                            let _ = child.kill();
                            warn!("Script execution timed out after {:?}", timeout);
                            return (false, "Script execution timed out".to_string());
                        }
                        // Sleep briefly before checking again
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        warn!("Error waiting for script: {}", e);
                        return (false, format!("Script execution error: {}", e));
                    }
                }
            }
        });

        match result.await {
            Ok(res) => res,
            Err(e) => {
                warn!("Script execution task failed: {}", e);
                (false, "Script execution failed".to_string())
            }
        }
    }
}

impl RuleEngineTrait for ScriptRuleEngine {
    async fn evaluate(&self, method: Method, url: &str) -> EvaluationResult {
        let (allowed, context) = self.execute_script(method.clone(), url).await;

        if allowed {
            info!("ALLOW: {} {} (script allowed)", method, url);
            let mut result = EvaluationResult::allow();
            if !context.is_empty() {
                result = result.with_context(context);
            }
            result
        } else {
            warn!("DENY: {} {} (script denied)", method, url);
            let mut result = EvaluationResult::deny();
            if !context.is_empty() {
                result = result.with_context(context);
            }
            result
        }
    }

    fn name(&self) -> &str {
        "script"
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

        let engine = ScriptRuleEngine::new(script_path.to_str().unwrap().to_string());
        let result = engine
            .evaluate(Method::GET, "https://example.com/test")
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

        let engine = ScriptRuleEngine::new(script_path.to_str().unwrap().to_string());
        let result = engine
            .evaluate(Method::GET, "https://example.com/test")
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

        let engine = ScriptRuleEngine::new(script_path.to_str().unwrap().to_string());
        let result = engine
            .evaluate(Method::GET, "https://example.com/test")
            .await;

        assert!(matches!(result.action, Action::Deny));
        assert_eq!(result.context, Some("Blocked by policy".to_string()));
        drop(script_path);
    }

    #[tokio::test]
    async fn test_script_environment_variables() {
        let mut script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/sh
if [ "$HTTPJAIL_HOST" = "allowed.com" ]; then
    exit 0
else
    echo "Host $HTTPJAIL_HOST not allowed"
    exit 1
fi
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

        let engine = ScriptRuleEngine::new(script_path.to_str().unwrap().to_string());

        let result = engine
            .evaluate(Method::GET, "https://allowed.com/test")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::GET, "https://blocked.com/test")
            .await;
        assert!(matches!(result.action, Action::Deny));
        assert_eq!(
            result.context,
            Some("Host blocked.com not allowed".to_string())
        );
        drop(script_path);
    }

    #[tokio::test]
    async fn test_inline_script() {
        let engine = ScriptRuleEngine::new("test \"$HTTPJAIL_HOST\" = \"github.com\"".to_string());

        let result = engine
            .evaluate(Method::GET, "https://github.com/test")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::GET, "https://example.com/test")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }
}
