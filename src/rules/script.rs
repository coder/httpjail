use super::{EvaluationResult, RuleEngineTrait};
use hyper::Method;
use std::process::Command;
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

    fn execute_script(&self, method: Method, url: &str) -> (bool, String) {
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

        let output = if self.script.contains(' ') {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
            Command::new(&shell)
                .arg("-c")
                .arg(&self.script)
                .env("HTTPJAIL_URL", url)
                .env("HTTPJAIL_METHOD", method.as_str())
                .env("HTTPJAIL_SCHEME", scheme)
                .env("HTTPJAIL_HOST", host)
                .env("HTTPJAIL_PATH", path)
                .output()
        } else {
            Command::new(&self.script)
                .env("HTTPJAIL_URL", url)
                .env("HTTPJAIL_METHOD", method.as_str())
                .env("HTTPJAIL_SCHEME", scheme)
                .env("HTTPJAIL_HOST", host)
                .env("HTTPJAIL_PATH", path)
                .output()
        };

        match output {
            Ok(output) => {
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
            Err(e) => {
                warn!("Failed to execute script: {}", e);
                (false, format!("Script execution failed: {}", e))
            }
        }
    }
}

impl RuleEngineTrait for ScriptRuleEngine {
    fn evaluate(&self, method: Method, url: &str) -> EvaluationResult {
        let (allowed, context) = self.execute_script(method.clone(), url);

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
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    #[test]
    fn test_script_allow() {
        let script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/sh
exit 0
"#;
        fs::write(script_file.path(), script).unwrap();

        let mut perms = fs::metadata(script_file.path()).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(script_file.path(), perms).unwrap();

        let engine = ScriptRuleEngine::new(script_file.path().to_str().unwrap().to_string());
        let result = engine.evaluate(Method::GET, "https://example.com/test");

        assert!(matches!(result.action, Action::Allow));
    }

    #[test]
    fn test_script_deny() {
        let script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/sh
exit 1
"#;
        fs::write(script_file.path(), script).unwrap();

        let mut perms = fs::metadata(script_file.path()).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(script_file.path(), perms).unwrap();

        let engine = ScriptRuleEngine::new(script_file.path().to_str().unwrap().to_string());
        let result = engine.evaluate(Method::GET, "https://example.com/test");

        assert!(matches!(result.action, Action::Deny));
    }

    #[test]
    fn test_script_with_context() {
        let script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/sh
echo "Blocked by policy"
exit 1
"#;
        fs::write(script_file.path(), script).unwrap();

        let mut perms = fs::metadata(script_file.path()).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(script_file.path(), perms).unwrap();

        let engine = ScriptRuleEngine::new(script_file.path().to_str().unwrap().to_string());
        let result = engine.evaluate(Method::GET, "https://example.com/test");

        assert!(matches!(result.action, Action::Deny));
        assert_eq!(result.context, Some("Blocked by policy".to_string()));
    }

    #[test]
    fn test_script_environment_variables() {
        let script_file = NamedTempFile::new().unwrap();
        let script = r#"#!/bin/sh
if [ "$HTTPJAIL_HOST" = "allowed.com" ]; then
    exit 0
else
    echo "Host $HTTPJAIL_HOST not allowed"
    exit 1
fi
"#;
        fs::write(script_file.path(), script).unwrap();

        let mut perms = fs::metadata(script_file.path()).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(script_file.path(), perms).unwrap();

        let engine = ScriptRuleEngine::new(script_file.path().to_str().unwrap().to_string());

        let result = engine.evaluate(Method::GET, "https://allowed.com/test");
        assert!(matches!(result.action, Action::Allow));

        let result = engine.evaluate(Method::GET, "https://blocked.com/test");
        assert!(matches!(result.action, Action::Deny));
        assert_eq!(
            result.context,
            Some("Host blocked.com not allowed".to_string())
        );
    }

    #[test]
    fn test_inline_script() {
        let engine = ScriptRuleEngine::new("test \"$HTTPJAIL_HOST\" = \"github.com\"".to_string());

        let result = engine.evaluate(Method::GET, "https://github.com/test");
        assert!(matches!(result.action, Action::Allow));

        let result = engine.evaluate(Method::GET, "https://example.com/test");
        assert!(matches!(result.action, Action::Deny));
    }
}
