use anyhow::{Context, Result};
use simple_dns::rdata::RData;
use simple_dns::{CLASS, Packet, PacketFlag, ResourceRecord, TYPE};
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
    for question in query.questions() {
        response.questions.push(question.clone());
    }

    // For each question, add a dummy A record response
    for question in query.questions() {
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
                assert_eq!(ip.a, 6);
                assert_eq!(ip.b, 6);
                assert_eq!(ip.c, 6);
                assert_eq!(ip.d, 6);
            } else {
                panic!("Expected A record in response");
            }
        } else {
            panic!("No answer in response");
        }
    }
}
