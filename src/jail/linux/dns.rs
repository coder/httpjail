use anyhow::{Context, Result};
use tracing::{debug, info};

/// Manages a forked child process that runs a DNS server inside a network namespace
///
/// This struct handles the lifecycle of a forked process that:
/// 1. Enters a specified network namespace
/// 2. Runs a DummyDnsServer on port 53
/// 3. Uses PR_SET_PDEATHSIG for automatic cleanup when parent dies
/// 4. Can be explicitly stopped via Drop trait
pub struct ForkedDnsProcess {
    /// PID of the forked child process
    child_pid: Option<nix::unistd::Pid>,
}

impl ForkedDnsProcess {
    pub fn new() -> Self {
        Self { child_pid: None }
    }

    /// Start a DNS server in a forked process within the specified namespace
    pub fn start(&mut self, namespace_name: &str) -> Result<()> {
        use nix::unistd::ForkResult;

        info!("Starting in-namespace DNS server for {}", namespace_name);

        // SAFETY: Fork is safe here because the child immediately execs,
        // avoiding any issues with locks or multi-threaded state
        match unsafe { nix::unistd::fork() }.context("Failed to fork DNS process")? {
            ForkResult::Child => {
                // Child process: Immediately exec to avoid multi-threaded fork issues

                // Close all unnecessary file descriptors inherited from parent
                // This is async-signal-safe
                for fd in 3..1024 {
                    unsafe {
                        libc::close(fd);
                    }
                }

                // Request SIGTERM when parent dies (async-signal-safe)
                unsafe {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                }

                // Check if parent already died (async-signal-safe)
                if unsafe { libc::getppid() } == 1 {
                    std::process::exit(1);
                }

                // Exec ourselves with the DNS server flag
                // This avoids all unsafe operations after fork in a multi-threaded runtime
                let exe_path = std::env::current_exe()
                    .unwrap_or_else(|_| std::path::PathBuf::from("/proc/self/exe"));

                let namespace_arg = format!("--__internal-dns-server={}", namespace_name);
                let args = vec![exe_path.to_string_lossy().into_owned(), namespace_arg];

                // Convert args to C strings
                let c_args: Vec<std::ffi::CString> = args
                    .iter()
                    .map(|s| std::ffi::CString::new(s.as_str()).unwrap())
                    .collect();

                let mut argv: Vec<*const libc::c_char> =
                    c_args.iter().map(|s| s.as_ptr()).collect();
                argv.push(std::ptr::null());

                // Exec (this never returns on success)
                unsafe {
                    libc::execv(c_args[0].as_ptr(), argv.as_ptr());
                    // If we get here, exec failed
                    libc::_exit(1);
                }
            }
            ForkResult::Parent { child } => {
                // Parent: Just store child PID
                self.child_pid = Some(child);
                info!("Started in-namespace DNS server (pid {})", child);
                Ok(())
            }
        }
    }

    /// Stop the forked DNS server
    pub fn stop(&mut self) {
        if let Some(pid) = self.child_pid.take() {
            use nix::sys::signal::{Signal, kill};
            use nix::sys::wait::waitpid;

            // Just kill the process - it's only sleeping, nothing to clean up
            let _ = kill(pid, Signal::SIGKILL);
            let _ = waitpid(pid, None);
            debug!("Stopped in-namespace DNS server (pid {})", pid);
        }
    }
}

impl Drop for ForkedDnsProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{Name, Question, TYPE};

    #[test]
    fn test_dns_response_builder() {
        // Create a test query using simple-dns
        let mut query = Packet::new_query(0x1234);
        let qname = Name::new("google.com").unwrap();
        query.questions.push(Question::new(
            qname.clone(),
            TYPE::A.into(),
            CLASS::IN.into(),
            false,
        ));

        // Build the response
        let response_packet = build_dummy_response(query.clone()).unwrap();

        // Parse the response back
        let response = Packet::parse(&response_packet).unwrap();

        // Verify the response
        assert_eq!(response.id(), 0x1234);
        assert!(response.has_flags(PacketFlag::RESPONSE));
        assert_eq!(response.questions.len(), 1);
        assert_eq!(response.answers.len(), 1);

        // Check that the answer contains our dummy IP
        if let Some(answer) = response.answers.first() {
            if let RData::A(ip) = &answer.rdata {
                assert_eq!(Ipv4Addr::from(ip.address), DUMMY_IPV4);
            } else {
                panic!("Expected A record in response");
            }
        } else {
            panic!("No answer in response");
        }
    }
}
