use super::{EvaluationResult, RuleEngineTrait};
use async_trait::async_trait;
use hyper::Method;
use std::time::Duration;
use tracing::debug;
use url::Url;

const MAX_RULE_OUTPUT: usize = 64 * 1024;

async fn read_bounded_output<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    reader
        .take((MAX_RULE_OUTPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_RULE_OUTPUT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Rule output exceeds 64 KiB",
        ));
    }
    Ok(bytes)
}

#[derive(Clone)]
pub struct ShellRuleEngine {
    script: String,
    restricted: bool,
}

impl ShellRuleEngine {
    pub fn new(script: String) -> Self {
        ShellRuleEngine {
            script,
            restricted: false,
        }
    }

    pub fn restricted(mut self) -> Self {
        self.restricted = true;
        self
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
        let mut cmd = if self.restricted {
            let mut cmd = tokio::process::Command::new("/usr/bin/setpriv");
            cmd.args([
                "--no-new-privs",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "--",
                &self.script,
            ]);
            cmd
        } else if self.script.contains(' ') {
            let mut cmd = tokio::process::Command::new("sh");
            cmd.arg("-c").arg(&self.script);
            cmd
        } else {
            tokio::process::Command::new(&self.script)
        };

        if self.restricted {
            cmd.env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        }

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
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                debug!("Failed to spawn script: {}", e);
                return (false, format!("Script execution failed: {}", e));
            }
        };

        // Drain both pipes concurrently, but fail as soon as either exceeds the
        // limit. wait_with_output would buffer an unbounded stream until timeout.
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let output = async {
            let (stdout, stderr) =
                tokio::try_join!(read_bounded_output(stdout), read_bounded_output(stderr))?;
            let status = child.wait().await?;
            Ok::<_, std::io::Error>((status, stdout, stderr))
        };
        let timeout = Duration::from_secs(30);
        match tokio::time::timeout(timeout, output).await {
            Ok(Ok((status, stdout, stderr))) => {
                let stdout = String::from_utf8_lossy(&stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&stderr).trim().to_string();

                if !stderr.is_empty() {
                    debug!("Script stderr: {}", stderr);
                }

                let allowed = status.success();

                debug!(
                    "Script returned {} for {} {} (exit code: {:?})",
                    if allowed { "ALLOW" } else { "DENY" },
                    method,
                    url,
                    status.code()
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_restricted_rule_runs_without_root() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let engine = ShellRuleEngine::new("/usr/bin/id".to_string()).restricted();
        let (allowed, stdout) = engine
            .execute_script(Method::GET, "https://example.invalid/", "127.0.0.1")
            .await;
        assert!(allowed, "{stdout}");
        assert!(stdout.contains("uid=65534"), "{stdout}");
    }

    #[tokio::test]
    async fn unbounded_rule_output_is_rejected() {
        let error = read_bounded_output(tokio::io::repeat(b'x'))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

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
