use anyhow::{Context, Result};
use simple_dns::{CLASS, Packet, PacketFlag, QCLASS, QTYPE, ResourceRecord, TYPE, rdata::RData};
use std::fs::OpenOptions;
use std::net::{Ipv4Addr, UdpSocket};
use tracing::{debug, info, warn};

const DUMMY_IPV4: Ipv4Addr = Ipv4Addr::new(6, 6, 6, 6);

// Security limits
const MAX_DNS_PACKET_SIZE: usize = 4096; // Support EDNS0
const MAX_DNS_QUESTIONS: usize = 10; // Limit questions per query
const DNS_BUFFER_SIZE: usize = 4096; // Buffer size for receiving packets

// UID/GID for nobody user (will try dynamic lookup first)
const FALLBACK_NOBODY_UID: u32 = 65534;
const FALLBACK_NOBODY_GID: u32 = 65534;

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
        // Validate namespace name to prevent injection attacks
        validate_namespace_name(namespace_name)?;
        use nix::unistd::ForkResult;

        info!("Starting in-namespace DNS server for {}", namespace_name);

        // SAFETY: Fork is safe here because the child immediately execs,
        // avoiding any issues with locks or multi-threaded state
        match unsafe { nix::unistd::fork() }.context("Failed to fork DNS process")? {
            ForkResult::Child => {
                // Child process: Immediately exec to avoid multi-threaded fork issues

                // Close all unnecessary file descriptors inherited from parent
                // Use close_range if available (Linux 5.9+), otherwise iterate through /proc/self/fd
                close_excess_fds();

                // Request SIGTERM when parent dies (async-signal-safe)
                // This must be done before checking parent PID to avoid race
                if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } != 0 {
                    std::process::exit(1);
                }

                // Check if parent already died (async-signal-safe)
                // After PR_SET_PDEATHSIG, we'll get SIGTERM if parent is gone
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

    // Drop privileges to nobody (with proper error checking)
    drop_privileges_to_nobody()?;

    // Run simple DNS server loop
    let mut buf = [0u8; DNS_BUFFER_SIZE];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                // Validate packet size before processing
                if size > MAX_DNS_PACKET_SIZE {
                    debug!("Dropping oversized DNS packet: {} bytes", size);
                    continue;
                }

                // Build minimal DNS response with dummy IP
                match build_dummy_response(&buf[..size]) {
                    Ok(response) => {
                        if let Err(e) = socket.send_to(&response, src) {
                            debug!("Failed to send DNS response: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to build DNS response: {}", e);
                    }
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
    // Validate packet size first
    if query.len() > MAX_DNS_PACKET_SIZE {
        return Err(anyhow::anyhow!("DNS packet too large"));
    }

    let query_packet = Packet::parse(query)?;
    let mut response = Packet::new_reply(query_packet.id());

    // Copy query flags
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER);

    // Limit the number of questions we'll process to prevent DoS
    let questions_to_copy: Vec<_> = query_packet
        .questions
        .iter()
        .take(MAX_DNS_QUESTIONS)
        .cloned()
        .collect();
    response.questions = questions_to_copy;

    // Add dummy answer for A record queries (limited to prevent response amplification)
    for question in response.questions.iter().take(MAX_DNS_QUESTIONS) {
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

    let response_bytes = response.build_bytes_vec()?;

    // Ensure response isn't too large
    if response_bytes.len() > MAX_DNS_PACKET_SIZE {
        return Err(anyhow::anyhow!("DNS response too large"));
    }

    Ok(response_bytes)
}

/// Validate namespace name to prevent injection attacks
fn validate_namespace_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 {
        return Err(anyhow::anyhow!("Invalid namespace name length"));
    }

    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(anyhow::anyhow!("Invalid characters in namespace name"));
    }

    Ok(())
}

/// Close excess file descriptors safely
fn close_excess_fds() {
    // Try to use close_range syscall if available (Linux 5.9+)
    #[cfg(target_os = "linux")]
    unsafe {
        // Define close_range flags
        const CLOSE_RANGE_UNSHARE: libc::c_uint = 0x02;

        // Try close_range syscall (syscall number 436 on x86_64)
        let ret = libc::syscall(
            436, // SYS_close_range
            3 as libc::c_uint,
            libc::c_uint::MAX,
            CLOSE_RANGE_UNSHARE,
        );

        if ret == 0 {
            return; // Success
        }

        // Fallback to manual closing if close_range is not available
        // Read /proc/self/fd to get actual open file descriptors
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(fd) = name.parse::<libc::c_int>() {
                        if fd > 2 {
                            libc::close(fd);
                        }
                    }
                }
            }
        } else {
            // Final fallback: close a reasonable range
            for fd in 3..256 {
                libc::close(fd);
            }
        }
    }
}

/// Drop privileges to nobody user with proper error checking
fn drop_privileges_to_nobody() -> Result<()> {
    unsafe {
        // Try to get nobody UID/GID dynamically
        let (uid, gid) = get_nobody_ids();

        // Drop supplementary groups
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(anyhow::anyhow!(
                "Failed to drop supplementary groups: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Set GID first (must be done before UID)
        if libc::setgid(gid) != 0 {
            return Err(anyhow::anyhow!(
                "Failed to set GID to {}: {}",
                gid,
                std::io::Error::last_os_error()
            ));
        }

        // Set UID (this drops all privileges)
        if libc::setuid(uid) != 0 {
            return Err(anyhow::anyhow!(
                "Failed to set UID to {}: {}",
                uid,
                std::io::Error::last_os_error()
            ));
        }

        // Re-establish parent death signal after credential change
        // PR_SET_PDEATHSIG is cleared when credentials change (setuid/setgid)
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
            warn!("Failed to re-establish parent death signal after dropping privileges");
        }

        // Verify privileges were actually dropped
        if libc::getuid() == 0 || libc::geteuid() == 0 {
            return Err(anyhow::anyhow!("Failed to drop root privileges"));
        }
    }

    Ok(())
}

/// Get nobody user UID/GID, with fallback to hardcoded values
fn get_nobody_ids() -> (u32, u32) {
    // Try to look up nobody user dynamically
    unsafe {
        let nobody_cstr = std::ffi::CString::new("nobody").unwrap();
        let pwd = libc::getpwnam(nobody_cstr.as_ptr());

        if !pwd.is_null() {
            return ((*pwd).pw_uid, (*pwd).pw_gid);
        }
    }

    // Fallback to common values
    (FALLBACK_NOBODY_UID, FALLBACK_NOBODY_GID)
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{Name, Question};

    #[test]
    fn test_namespace_validation() {
        assert!(validate_namespace_name("httpjail_123").is_ok());
        assert!(validate_namespace_name("test-namespace_1").is_ok());
        assert!(validate_namespace_name("").is_err());
        assert!(validate_namespace_name("../etc/passwd").is_err());
        assert!(validate_namespace_name("name with spaces").is_err());
        assert!(validate_namespace_name("name;rm -rf /").is_err());
        assert!(validate_namespace_name(&"a".repeat(256)).is_err());
    }

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

    #[test]
    fn test_oversized_packet_rejection() {
        // Create an oversized buffer
        let oversized = vec![0u8; MAX_DNS_PACKET_SIZE + 1];
        let result = build_dummy_response(&oversized);
        assert!(result.is_err());
    }

    #[test]
    fn test_question_limit() {
        // Create a query with many questions
        let mut query = Packet::new_query(0x5678);

        // Add more questions than the limit
        // Use a single domain name to avoid lifetime issues
        let qname = Name::new("test.com").unwrap();
        for _ in 0..(MAX_DNS_QUESTIONS + 5) {
            query.questions.push(Question::new(
                qname.clone(),
                TYPE::A.into(),
                CLASS::IN.into(),
                false,
            ));
        }

        let query_bytes = query.build_bytes_vec().unwrap();
        let response_bytes = build_dummy_response(&query_bytes).unwrap();
        let response = Packet::parse(&response_bytes).unwrap();

        // Verify that only MAX_DNS_QUESTIONS were processed
        assert_eq!(response.questions.len(), MAX_DNS_QUESTIONS);
        assert_eq!(response.answers.len(), MAX_DNS_QUESTIONS);
    }
}
