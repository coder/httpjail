use anyhow::{Context, Result};
use simple_dns::{CLASS, Packet, PacketFlag, QCLASS, QTYPE, ResourceRecord, TYPE, rdata::RData};
use std::fs::OpenOptions;
use std::net::{Ipv4Addr, UdpSocket};
use tracing::{debug, info};

const DUMMY_IPV4: Ipv4Addr = Ipv4Addr::new(6, 6, 6, 6);

/// Manages a forked child process that runs a DNS server inside a network namespace
///
/// This struct handles the lifecycle of a forked process that:
/// 1. Enters a specified network namespace
/// 2. Runs a DummyDnsServer on port 53
/// 3. Uses PR_SET_PDEATHSIG for automatic cleanup when parent dies
/// 4. Can be explicitly stopped via Drop trait
#[derive(Default)]
pub struct ForkedDnsProcess {
    /// PID of the forked child process
    child_pid: Option<nix::unistd::Pid>,
}

impl ForkedDnsProcess {
    pub fn new() -> Self {
        Self::default()
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
                let args = [exe_path.to_string_lossy().into_owned(), namespace_arg];

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

/// Run the DNS server in the namespace after exec.
/// This is called from main() when the --__internal-dns-server flag is present.
pub fn run_exec_dns_server(namespace_name: &str) -> Result<()> {
    // Enter the namespace
    let ns_path = format!("/var/run/netns/{}", namespace_name);
    let ns_fd = OpenOptions::new()
        .read(true)
        .open(&ns_path)
        .with_context(|| format!("Failed to open namespace {}", ns_path))?;

    // Enter the namespace using nix
    use nix::sched::CloneFlags;
    nix::sched::setns(&ns_fd, CloneFlags::CLONE_NEWNET)
        .context("Failed to enter network namespace")?;

    // Bring up loopback interface
    std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .output()
        .context("Failed to bring up loopback")?;

    // Bind DNS socket
    let socket =
        UdpSocket::bind("0.0.0.0:53").context("Failed to bind DNS server to 0.0.0.0:53")?;

    socket.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;

    // Drop privileges to nobody
    unsafe {
        libc::setgroups(0, std::ptr::null());
        libc::setgid(65534); // nogroup
        libc::setuid(65534); // nobody
    }

    // Run simple DNS server loop
    let mut buf = [0u8; 512];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                // Build minimal DNS response with dummy IP
                if let Ok(response) = build_dummy_response(&buf[..size]) {
                    let _ = socket.send_to(&response, src);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    Ok(())
}

fn build_dummy_response(query: &[u8]) -> Result<Vec<u8>> {
    let query_packet = Packet::parse(query)?;
    let mut response = Packet::new_reply(query_packet.id());

    // Copy query flags
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);
    response.questions = query_packet.questions.clone();

    // Add dummy answer for all A record queries
    for question in &query_packet.questions {
        if question.qtype == QTYPE::TYPE(TYPE::A) && question.qclass == QCLASS::CLASS(CLASS::IN) {
            let answer = ResourceRecord::new(
                question.qname.clone(),
                CLASS::IN,
                300, // TTL
                RData::A(DUMMY_IPV4.into()),
            );
            response.answers.push(answer);
        }
    }

    Ok(response.build_bytes_vec()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{Name, Question};

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
        let query_bytes = query.build_bytes_vec().unwrap();
        let response_packet = build_dummy_response(&query_bytes).unwrap();

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
