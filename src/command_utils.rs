use anyhow::Context;
use std::process::{Command, Output};
use std::time::Duration;
use tracing::debug;

/// Result of executing a command with timeout
/// This is a specialized Result type that avoids nesting
#[derive(Debug)]
pub enum CommandResult {
    /// Command completed execution (may have succeeded or failed)
    Completed(Output),
    /// Command was terminated due to timeout
    TimedOut {
        /// Any stdout captured before timeout
        stdout: Vec<u8>,
        /// Any stderr captured before timeout  
        stderr: Vec<u8>,
        /// How long we waited before timing out
        duration: Duration,
    },
    /// Failed to spawn or execute the command
    Error(anyhow::Error),
}

impl CommandResult {
    /// Map an anyhow::Result to CommandResult::Error
    fn from_result<T, F>(result: anyhow::Result<T>, f: F) -> Self
    where
        F: FnOnce(T) -> Self,
    {
        match result {
            Ok(value) => f(value),
            Err(e) => CommandResult::Error(e),
        }
    }
    /// Check if the command timed out
    pub fn is_timeout(&self) -> bool {
        matches!(self, CommandResult::TimedOut { .. })
    }

    /// Check if the command completed successfully (exit code 0)
    /// Returns false for timeout, errors, or non-zero exit codes
    pub fn is_success(&self) -> bool {
        match self {
            CommandResult::Completed(output) => output.status.success(),
            CommandResult::TimedOut { .. } | CommandResult::Error(_) => false,
        }
    }

    /// Check if this was an error (failed to spawn/execute)
    pub fn is_error(&self) -> bool {
        matches!(self, CommandResult::Error(_))
    }

    /// Get the error if this was an execution error
    pub fn error(&self) -> Option<&anyhow::Error> {
        match self {
            CommandResult::Error(e) => Some(e),
            _ => None,
        }
    }

    /// Get the exit code if the command completed
    /// Returns None for timeouts or errors
    pub fn exit_code(&self) -> Option<i32> {
        match self {
            CommandResult::Completed(output) => output.status.code(),
            CommandResult::TimedOut { .. } | CommandResult::Error(_) => None,
        }
    }

    /// Get stdout bytes
    pub fn stdout(&self) -> &[u8] {
        match self {
            CommandResult::Completed(output) => &output.stdout,
            CommandResult::TimedOut { stdout, .. } => stdout,
            CommandResult::Error(_) => &[],
        }
    }

    /// Get stderr bytes
    pub fn stderr(&self) -> &[u8] {
        match self {
            CommandResult::Completed(output) => &output.stderr,
            CommandResult::TimedOut { stderr, .. } => stderr,
            CommandResult::Error(_) => &[],
        }
    }

    /// Get stderr as string
    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(self.stderr()).to_string()
    }
}

/// Execute a command with a timeout using tokio's async runtime.
///
/// This function can be called from either sync or async contexts.
/// It uses tokio::task::block_in_place to efficiently run async code
/// in a blocking manner without spawning new threads when possible.
///
/// Returns `CommandResult::Completed` if the command finishes (successfully or not),
/// `CommandResult::TimedOut` if the timeout expires, or `CommandResult::Error` if
/// the command fails to spawn.
pub fn execute_with_timeout(command: Command, timeout_duration: Duration) -> CommandResult {
    // Get program and args before moving command
    let program = command.get_program().to_os_string();
    let args: Vec<_> = command.get_args().map(|s| s.to_os_string()).collect();

    // Check if we're in a tokio runtime
    if tokio::runtime::Handle::try_current().is_ok() {
        // We're in a tokio runtime, use block_in_place for efficiency
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();

            handle.block_on(async move {
                execute_with_timeout_async(program, args, timeout_duration).await
            })
        })
    } else {
        // No runtime exists, create a temporary one
        CommandResult::from_result(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("Failed to create tokio runtime"),
            |rt| {
                rt.block_on(async move {
                    execute_with_timeout_async(program, args, timeout_duration).await
                })
            },
        )
    }
}

/// Internal async implementation of command execution with timeout
async fn execute_with_timeout_async(
    program: std::ffi::OsString,
    args: Vec<std::ffi::OsString>,
    timeout_duration: Duration,
) -> CommandResult {
    // Create tokio command
    let mut tokio_cmd = tokio::process::Command::new(&program);
    tokio_cmd.args(&args);
    tokio_cmd.stdout(std::process::Stdio::piped());
    tokio_cmd.stderr(std::process::Stdio::piped());
    tokio_cmd.kill_on_drop(true); // Automatically cleanup on drop

    // Spawn the command
    let child = match tokio_cmd.spawn().context("Failed to spawn command") {
        Ok(child) => child,
        Err(e) => return CommandResult::Error(e),
    };

    // Wait with timeout
    match tokio::time::timeout(timeout_duration, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            // Command completed within timeout
            CommandResult::Completed(output)
        }
        Ok(Err(e)) => {
            // Command failed to execute
            CommandResult::Error(e.into())
        }
        Err(_) => {
            // Timeout elapsed
            debug!("Command timed out after {:?}", timeout_duration);

            // Child is automatically killed due to kill_on_drop(true)
            CommandResult::TimedOut {
                stdout: Vec::new(),
                stderr: format!("Command timed out after {:?}", timeout_duration).into_bytes(),
                duration: timeout_duration,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests need to run within multi-threaded tokio runtime for block_in_place
    #[tokio::test(flavor = "multi_thread")]
    async fn test_command_completes_before_timeout() {
        let mut cmd = Command::new("echo");
        cmd.arg("hello");

        let result = execute_with_timeout(cmd, Duration::from_secs(5));
        assert!(!result.is_error());
        assert!(result.is_success());
        assert!(!result.is_timeout());
        assert_eq!(String::from_utf8_lossy(result.stdout()).trim(), "hello");

        // Test exit code getter
        assert_eq!(result.exit_code(), Some(0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_command_times_out() {
        let mut cmd = Command::new("sleep");
        cmd.arg("10");

        let result = execute_with_timeout(cmd, Duration::from_secs(1));
        assert!(!result.is_error());
        assert!(result.is_timeout());
        assert!(!result.is_success());

        // The stderr should contain timeout message
        let stderr_str = result.stderr_string();
        assert!(stderr_str.contains("timed out"));

        // Timeout should have no exit code
        assert_eq!(result.exit_code(), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_command_fails_with_exit_code() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "exit 42"]);

        let result = execute_with_timeout(cmd, Duration::from_secs(5));
        assert!(!result.is_error());
        assert!(!result.is_timeout());
        assert!(!result.is_success());
        assert_eq!(result.exit_code(), Some(42));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_command_spawn_error() {
        let mut cmd = Command::new("/nonexistent/command");
        cmd.arg("test");

        let result = execute_with_timeout(cmd, Duration::from_secs(5));
        assert!(result.is_error());
        assert!(!result.is_timeout());
        assert!(!result.is_success());
        assert!(result.error().is_some());
    }
}
