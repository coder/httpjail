use anyhow::{Context, Result};
use std::ffi::CString;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::ptr;
use tracing::debug;

/// Execute a command with specific UID/GID settings using fork/exec
/// This gives us precise control over the order of privilege dropping
pub unsafe fn fork_exec_with_gid(
    command: &[String],
    gid: u32,
    target_uid: Option<u32>,
    extra_env: &[(String, String)],
) -> Result<ExitStatus> {
    // Prepare command and arguments
    let prog = CString::new(command[0].as_bytes()).context("Invalid program path")?;
    let args: Result<Vec<CString>> = command
        .iter()
        .map(|s| CString::new(s.as_bytes()).context("Invalid argument"))
        .collect();
    let args = args?;
    let mut arg_ptrs: Vec<*const libc::c_char> = args.iter().map(|s| s.as_ptr()).collect();
    arg_ptrs.push(ptr::null());

    // Set extra environment variables in current process
    // execvp will inherit the environment
    for (key, val) in extra_env {
        std::env::set_var(key, val);
    }

    // Fork the process
    let pid = libc::fork();
    if pid < 0 {
        anyhow::bail!("Fork failed: {}", std::io::Error::last_os_error());
    } else if pid == 0 {
        // Child process
        child_process(prog.as_ptr(), arg_ptrs.as_ptr(), gid, target_uid);
        // child_process never returns
    } else {
        // Parent process - wait for child
        parent_wait(pid)
    }
}

/// Child process logic - sets up GID/UID and execs
/// This function never returns normally - it either execs or exits
unsafe fn child_process(
    prog: *const libc::c_char,
    args: *const *const libc::c_char,
    gid: u32,
    target_uid: Option<u32>,
) -> ! {
    // CRITICAL: Set GID first, before dropping privileges
    // This sets both real and effective GID
    if libc::setgid(gid) != 0 {
        debug!(
            "setgid({}) failed: {}",
            gid,
            std::io::Error::last_os_error()
        );
        libc::_exit(1);
    }

    // On macOS, don't drop supplementary groups as it interferes with EGID
    // The setgroups() call can cause issues with effective GID preservation
    // Comment out for now - we rely on setgid/setuid for security
    /*
    let groups_result = libc::setgroups(0, ptr::null());
    if groups_result != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EPERM) {
            debug!("setgroups(0) failed: {}", err);
            libc::_exit(1);
        }
    }
    */

    // If we have a target UID, drop privileges to that user
    // Do this AFTER setgid to preserve the effective GID
    if let Some(uid) = target_uid {
        if libc::setuid(uid) != 0 {
            debug!(
                "setuid({}) failed: {}",
                uid,
                std::io::Error::last_os_error()
            );
            libc::_exit(1);
        }
    }

    // Execute the program using execvp to search PATH
    libc::execvp(prog, args);

    // If we get here, exec failed
    debug!("execvp failed: {}", std::io::Error::last_os_error());
    libc::_exit(127);
}

/// Parent process logic - wait for child and return exit status
unsafe fn parent_wait(pid: libc::pid_t) -> Result<ExitStatus> {
    let mut status: libc::c_int = 0;
    let wait_result = libc::waitpid(pid, &mut status, 0);

    if wait_result < 0 {
        anyhow::bail!("waitpid failed: {}", std::io::Error::last_os_error());
    }

    // Convert to ExitStatus
    Ok(ExitStatus::from_raw(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fork_exec_simple() {
        // This test would need to run as root to properly test GID setting
        // For now, just test that the function compiles and basic execution works
        unsafe {
            let result = fork_exec_with_gid(
                &vec!["echo".to_string(), "test".to_string()],
                0,    // Use current GID
                None, // No UID change
                &[],
            );
            assert!(result.is_ok());
            assert!(result.unwrap().success());
        }
    }
}
