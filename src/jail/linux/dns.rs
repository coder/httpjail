use anyhow::{Context, Result};
use simple_dns::rdata::RData;
use simple_dns::{CLASS, Packet, PacketFlag, ResourceRecord};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
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

/// A DNS server that runs in a forked process inside a network namespace
pub struct NamespaceDnsServer {
    /// PID of the forked DNS server process
    dns_forwarder_pid: Option<libc::pid_t>,
    /// File descriptor of the pipe used to signal shutdown
    dns_cleanup_pipe: Option<RawFd>,
}

impl NamespaceDnsServer {
    pub fn new() -> Self {
        Self {
            dns_forwarder_pid: None,
            dns_cleanup_pipe: None,
        }
    }

    /// Start a DNS server in a forked process within the specified namespace
    pub fn start(&mut self, namespace_name: &str) -> Result<()> {
        info!("Starting in-namespace DNS server for {}", namespace_name);

        // Create pipe for cleanup detection
        let (read_fd, write_fd) = nix::unistd::pipe().context("Failed to create cleanup pipe")?;

        // SAFETY: While we may be forking from within a tokio runtime, this is safe because:
        // 1. The child process immediately drops all Rust objects except raw file descriptors
        // 2. It only uses libc calls and never returns to Rust/tokio code
        // 3. It exits via std::process::exit() or libc::exit(), never unwinding
        // 4. The parent continues normally with its own file descriptors
        //
        // To make this even safer, we could use std::process::Command instead of fork(),
        // but that would require a separate binary or significant refactoring.
        match unsafe { libc::fork() } {
            0 => {
                // Child: Run DNS server in namespace
                drop(write_fd);
                let read_raw = read_fd.as_raw_fd();

                // Close all unnecessary file descriptors inherited from parent
                // This includes tokio's epoll/kqueue fds and any other open files
                // Keep only stdin(0), stdout(1), stderr(2), and our read pipe
                for fd in 3..1024 {
                    if fd != read_raw {
                        unsafe {
                            libc::close(fd);
                        }
                    }
                }

                // Die if parent dies
                unsafe {
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                    if libc::getppid() == 1 {
                        libc::exit(1);
                    }
                }

                // Enter the namespace
                let ns_path = format!("/var/run/netns/{}", namespace_name);
                let ns_fd = std::fs::File::open(&ns_path).unwrap_or_else(|e| {
                    eprintln!("Failed to open namespace {}: {}", ns_path, e);
                    std::process::exit(1);
                });

                let ret = unsafe { libc::setns(ns_fd.as_raw_fd(), libc::CLONE_NEWNET) };
                if ret != 0 {
                    eprintln!("Failed to setns into {}", namespace_name);
                    std::process::exit(1);
                }

                // Ensure loopback interface is up
                std::process::Command::new("ip")
                    .args(["link", "set", "lo", "up"])
                    .output()
                    .ok();

                // Start DNS server on all interfaces (requires root for privileged port)
                let mut server = DummyDnsServer::new();
                if let Err(e) = server.start("0.0.0.0:53") {
                    eprintln!("Failed to start DNS server: {}", e);
                    std::process::exit(1);
                }

                // Drop privileges to nobody after binding
                unsafe {
                    libc::setgroups(0, std::ptr::null());
                    libc::setgid(65534); // nogroup
                    libc::setuid(65534); // nobody
                }

                info!("In-namespace DNS server listening on 0.0.0.0:53");

                // Monitor parent lifecycle
                loop {
                    let mut buf = [0u8; 1];
                    let n =
                        unsafe { libc::read(read_raw, buf.as_mut_ptr() as *mut libc::c_void, 1) };
                    if n == 0 {
                        // EOF - parent died
                        std::process::exit(0);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
            pid if pid > 0 => {
                // Parent: Store cleanup info
                drop(read_fd);
                let write_raw = write_fd.as_raw_fd();
                self.dns_forwarder_pid = Some(pid);
                self.dns_cleanup_pipe = Some(write_raw);
                // Keep write_fd alive by not dropping it
                std::mem::forget(write_fd);

                info!("Started in-namespace DNS server (pid {})", pid);
                Ok(())
            }
            _ => anyhow::bail!("Fork failed"),
        }
    }

    /// Stop the forked DNS server
    pub fn stop(&mut self) {
        // Close pipe to signal shutdown
        if let Some(fd) = self.dns_cleanup_pipe.take() {
            unsafe {
                libc::close(fd);
            }
        }

        // Clean kill of the process
        if let Some(pid) = self.dns_forwarder_pid.take() {
            unsafe {
                // Try graceful termination
                libc::kill(pid, libc::SIGTERM);

                // Wait briefly for clean exit
                let start = std::time::Instant::now();
                let mut status = 0;
                while start.elapsed() < std::time::Duration::from_millis(100) {
                    if libc::waitpid(pid, &mut status, libc::WNOHANG) == pid {
                        info!("Stopped in-namespace DNS server");
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }

                // Force kill if needed
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
                info!("Force-stopped in-namespace DNS server");
            }
        }
    }
}

impl Drop for NamespaceDnsServer {
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
