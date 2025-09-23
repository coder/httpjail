use anyhow::{Context, Result};
use std::process::{Command, Output};
use std::time::Duration;
use tracing::debug;

/// Execute a command with a timeout using tokio's async runtime.
///
/// This function can be called from either sync or async contexts.
/// It uses tokio::task::block_in_place to efficiently run async code
/// in a blocking manner without spawning new threads when possible.
pub fn execute_with_timeout(command: Command, timeout_duration: Duration) -> Result<Output> {
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
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime")?;

        rt.block_on(
            async move { execute_with_timeout_async(program, args, timeout_duration).await },
        )
    }
}

/// Internal async implementation of command execution with timeout
async fn execute_with_timeout_async(
    program: std::ffi::OsString,
    args: Vec<std::ffi::OsString>,
    timeout_duration: Duration,
) -> Result<Output> {
    // Create tokio command
    let mut tokio_cmd = tokio::process::Command::new(&program);
    tokio_cmd.args(&args);
    tokio_cmd.stdout(std::process::Stdio::piped());
    tokio_cmd.stderr(std::process::Stdio::piped());
    tokio_cmd.kill_on_drop(true); // Automatically cleanup on drop

    // Spawn the command
    let child = tokio_cmd.spawn().context("Failed to spawn command")?;

    // Wait with timeout
    match tokio::time::timeout(timeout_duration, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            // Command completed successfully within timeout
            Ok(output)
        }
        Ok(Err(e)) => {
            // Command failed to execute
            Err(e).context("Command execution failed")
        }
        Err(_) => {
            // Timeout elapsed
            debug!("Command timed out after {:?}", timeout_duration);

            // Child is automatically killed due to kill_on_drop(true)
            // Return a synthetic output that matches GNU timeout behavior
            Ok(Output {
                status: create_timeout_exit_status(),
                stdout: Vec::new(),
                stderr: format!("Command timed out after {:?}", timeout_duration).into_bytes(),
            })
        }
    }
}

/// Create an exit status that indicates timeout (exit code 124)
/// This matches the behavior of GNU timeout command
#[cfg(unix)]
fn create_timeout_exit_status() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(124 << 8) // Exit code in high byte
}

#[cfg(not(unix))]
fn create_timeout_exit_status() -> std::process::ExitStatus {
    // On non-Unix, we can't easily create a specific exit status
    // Just return a failed status - the stderr will indicate timeout
    std::process::Command::new("false")
        .status()
        .unwrap_or_else(|_| {
            // If even false doesn't exist, create any non-success status
            std::process::Command::new("cmd")
                .args(["/c", "exit 124"])
                .status()
                .unwrap()
        })
}

// For backward compatibility, keep the old name as an alias
pub use execute_with_timeout as execute_with_timeout_poll;

#[cfg(test)]
mod tests {
    use super::*;

    // Tests need to run within multi-threaded tokio runtime for block_in_place
    #[tokio::test(flavor = "multi_thread")]
    async fn test_command_completes_before_timeout() {
        let mut cmd = Command::new("echo");
        cmd.arg("hello");

        let result = execute_with_timeout(cmd, Duration::from_secs(5)).unwrap();
        assert!(result.status.success());
        assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), "hello");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_command_times_out() {
        let mut cmd = Command::new("sleep");
        cmd.arg("10");

        let result = execute_with_timeout(cmd, Duration::from_secs(1)).unwrap();
        // On timeout, the process is killed, so status won't be success
        assert!(!result.status.success());
        // The stderr should contain timeout message
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("timed out"));

        // On Unix, check for exit code 124
        #[cfg(unix)]
        assert_eq!(result.status.code(), Some(124));
    }
}
