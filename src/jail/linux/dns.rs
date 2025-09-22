use anyhow::{Context, Result};
use simple_dns::rdata::RData;
use simple_dns::{CLASS, Packet, PacketFlag, ResourceRecord};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

const DUMMY_IPV4: Ipv4Addr = Ipv4Addr::new(6, 6, 6, 6);
const MAX_DNS_PACKET_SIZE: usize = 512;

pub struct DummyDnsServer {
    socket: Option<UdpSocket>,
    shutdown: Arc<AtomicBool>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl DummyDnsServer {
    pub fn new() -> Self {
        Self {
            socket: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            thread_handle: None,
        }
    }

    pub fn start(&mut self, bind_addr: &str) -> Result<()> {
        let socket = UdpSocket::bind(bind_addr)
            .with_context(|| format!("Failed to bind DNS server to {}", bind_addr))?;

        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        info!("Starting dummy DNS server on {}", bind_addr);

        let socket_clone = socket.try_clone()?;
        let shutdown_clone = self.shutdown.clone();

        let thread_handle = thread::spawn(move || {
            if let Err(e) = run_dns_server(socket_clone, shutdown_clone) {
                error!("DNS server error: {}", e);
            }
        });

        self.socket = Some(socket);
        self.thread_handle = Some(thread_handle);

        Ok(())
    }

    pub fn stop(&mut self) {
        debug!("Stopping dummy DNS server");
        self.shutdown.store(true, Ordering::Relaxed);

        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        self.socket = None;
    }
}

impl Drop for DummyDnsServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_dns_server(socket: UdpSocket, shutdown: Arc<AtomicBool>) -> Result<()> {
    let mut buf = [0u8; MAX_DNS_PACKET_SIZE];

    while !shutdown.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                debug!("Received DNS query from {}: {} bytes", src, size);

                // Parse the DNS query using simple-dns
                match Packet::parse(&buf[..size]) {
                    Ok(query) => {
                        if let Ok(response) = build_dummy_response(query) {
                            if let Err(e) = socket.send_to(&response, src) {
                                warn!("Failed to send DNS response to {}: {}", src, e);
                            } else {
                                debug!("Sent dummy DNS response to {}", src);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse DNS query: {}", e);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // EINTR can happen when signals are received, just retry
                continue;
            }
            Err(e) => {
                if !shutdown.load(Ordering::Relaxed) {
                    error!("DNS server receive error: {}", e);
                }
                break;
            }
        }
    }

    Ok(())
}

fn build_dummy_response(query: Packet<'_>) -> Result<Vec<u8>> {
    // Create a response packet based on the query
    let mut response = Packet::new_reply(query.id());

    // Set standard response flags
    response.set_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE);

    // Copy all questions from the query to the response
    for question in &query.questions {
        response.questions.push(question.clone());
    }

    // For each question, add a dummy A record response
    for question in &query.questions {
        // Only respond to A record queries (TYPE 1)
        // But we'll respond to all queries with an A record anyway
        // to prevent any DNS exfiltration attempts
        let answer = ResourceRecord::new(
            question.qname.clone(),
            CLASS::IN,
            60, // TTL in seconds
            RData::A(DUMMY_IPV4.into()),
        );
        response.answers.push(answer);
    }

    // Build the response packet into bytes
    response
        .build_bytes_vec()
        .map_err(|e| anyhow::anyhow!("Failed to build DNS response: {}", e))
}

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

        // SAFETY: While forking from a tokio runtime, the child immediately:
        // - Closes unnecessary file descriptors
        // - Sets PR_SET_PDEATHSIG for automatic cleanup when parent dies
        // - Never returns to Rust/tokio code
        // - Runs until terminated by signal
        match unsafe { nix::unistd::fork() }.context("Failed to fork DNS process")? {
            ForkResult::Child => {
                // Child process: Run DNS server in namespace

                // Close all unnecessary file descriptors inherited from parent
                // Keep only stdin(0), stdout(1), stderr(2)
                for fd in 3..1024 {
                    let _ = nix::unistd::close(fd);
                }

                // Request SIGTERM when parent dies
                #[cfg(target_os = "linux")]
                {
                    use nix::sys::signal::Signal;
                    if let Err(e) = nix::sys::prctl::set_pdeathsig(Signal::SIGTERM) {
                        eprintln!("Failed to set parent death signal: {}", e);
                        std::process::exit(1);
                    }
                }

                // Check if parent already died
                if nix::unistd::getppid() == nix::unistd::Pid::from_raw(1) {
                    std::process::exit(1);
                }

                // Enter the namespace
                let ns_path = format!("/var/run/netns/{}", namespace_name);
                let ns_fd = std::fs::File::open(&ns_path).unwrap_or_else(|e| {
                    eprintln!("Failed to open namespace {}: {}", ns_path, e);
                    std::process::exit(1);
                });

                // Use nix for setns
                nix::sched::setns(&ns_fd, nix::sched::CloneFlags::CLONE_NEWNET).unwrap_or_else(
                    |e| {
                        eprintln!("Failed to setns into {}: {}", namespace_name, e);
                        std::process::exit(1);
                    },
                );

                // Ensure loopback interface is up
                std::process::Command::new("ip")
                    .args(["link", "set", "lo", "up"])
                    .output()
                    .ok();

                // Bind DNS socket before dropping privileges
                let socket = match UdpSocket::bind("0.0.0.0:53") {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Failed to bind DNS server to 0.0.0.0:53: {}", e);
                        std::process::exit(1);
                    }
                };

                // Set read timeout to avoid blocking forever
                socket
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .ok();

                // Drop privileges to nobody after binding
                let nobody_uid = nix::unistd::Uid::from_raw(65534);
                let nogroup_gid = nix::unistd::Gid::from_raw(65534);

                nix::unistd::setgroups(&[]).ok();
                nix::unistd::setgid(nogroup_gid).ok();
                nix::unistd::setuid(nobody_uid).ok();

                // Run DNS server directly in this process
                let shutdown = Arc::new(AtomicBool::new(false));
                if let Err(e) = run_dns_server(socket, shutdown) {
                    eprintln!("DNS server error: {}", e);
                    std::process::exit(1);
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
