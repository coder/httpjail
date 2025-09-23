use anyhow::{Context, Result};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;
use tracing::debug;

/// Execute a command with a timeout using a polling approach.
///
/// This polls the child process status periodically and kills it if it
/// exceeds the specified timeout duration.
pub fn execute_with_timeout_poll(mut command: Command, timeout: Duration) -> Result<Output> {
    use std::time::Instant;

    // Spawn the command
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn command")?;

    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);

    // Poll until timeout or process exits
    loop {
        // Check if process has exited
        match child.try_wait() {
            Ok(Some(_)) => {
                // Process has exited, get the output
                return child
                    .wait_with_output()
                    .context("Failed to get command output");
            }
            Ok(None) => {
                // Process still running
                if start.elapsed() > timeout {
                    // Timeout reached, kill the process
                    debug!("Command timed out after {:?}, killing process", timeout);
                    let _ = child.kill();
                    // Wait and get the actual status (will be killed status)
                    let status = child.wait().unwrap_or_else(|_| {
                        // If we can't get status, create a synthetic one
                        // On Unix, use from_raw (platform-specific)
                        #[cfg(unix)]
                        {
                            use std::os::unix::process::ExitStatusExt;
                            std::process::ExitStatus::from_raw(124 * 256) // exit code 124 in high byte
                        }
                        #[cfg(not(unix))]
                        {
                            // On non-Unix, we can't create a synthetic exit status easily
                            panic!("Failed to get process status after timeout");
                        }
                    });

                    // Return output with timeout indication
                    return Ok(Output {
                        status,
                        stdout: Vec::new(),
                        stderr: format!("Command timed out after {:?}", timeout).into_bytes(),
                    });
                }
                // Sleep before next poll
                thread::sleep(poll_interval);
            }
            Err(e) => {
                // Error checking process status
                let _ = child.kill();
                return Err(anyhow::anyhow!("Failed to check process status: {}", e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_completes_before_timeout() {
        let mut cmd = Command::new("echo");
        cmd.arg("hello");

        let result = execute_with_timeout_poll(cmd, Duration::from_secs(5)).unwrap();
        assert!(result.status.success());
        assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), "hello");
    }

    #[test]
    fn test_command_times_out() {
        let mut cmd = Command::new("sleep");
        cmd.arg("10");

        let result = execute_with_timeout_poll(cmd, Duration::from_secs(1)).unwrap();
        // On timeout, the process is killed, so status won't be success
        assert!(!result.status.success());
        // The stderr should contain timeout message
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("timed out"));
    }
}
