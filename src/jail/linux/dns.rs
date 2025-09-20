use anyhow::{Context, Result};
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

                if size >= 12
                    && let Ok(response) = build_dummy_response(&buf[..size])
                {
                    if let Err(e) = socket.send_to(&response, src) {
                        warn!("Failed to send DNS response to {}: {}", src, e);
                    } else {
                        debug!("Sent dummy DNS response to {}", src);
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

fn build_dummy_response(query: &[u8]) -> Result<Vec<u8>> {
    if query.len() < 12 {
        anyhow::bail!("DNS query too short");
    }

    let mut response = Vec::with_capacity(512);

    response.extend_from_slice(&query[0..2]);

    let mut flags = ((query[2] as u16) << 8) | (query[3] as u16);
    flags |= 0x8000;
    flags &= !0x7800;
    flags &= !0x000F;

    response.push((flags >> 8) as u8);
    response.push((flags & 0xFF) as u8);

    // Copy question count from query
    response.extend_from_slice(&query[4..6]);

    response.push(0);
    response.push(1);

    response.push(0);
    response.push(0);
    response.push(0);
    response.push(0);

    let query_end = find_query_end(query, 12)?;
    response.extend_from_slice(&query[12..query_end]);

    response.push(0xC0);
    response.push(0x0C);

    response.push(0);
    response.push(1);

    response.push(0);
    response.push(1);

    response.push(0);
    response.push(0);
    response.push(0);
    response.push(60);

    response.push(0);
    response.push(4);

    response.extend_from_slice(&DUMMY_IPV4.octets());

    Ok(response)
}

fn find_query_end(packet: &[u8], start: usize) -> Result<usize> {
    let mut pos = start;

    while pos < packet.len() {
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len >= 0xC0 {
            pos += 2;
            break;
        }
        pos += len + 1;
    }

    if pos + 4 > packet.len() {
        anyhow::bail!("Malformed DNS query");
    }

    Ok(pos + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_response_builder() {
        let query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'g',
            b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let response = build_dummy_response(&query).unwrap();

        assert_eq!(response[0..2], query[0..2]);

        assert_eq!(response[2] & 0x80, 0x80);

        let answer_count = ((response[6] as u16) << 8) | (response[7] as u16);
        assert_eq!(answer_count, 1);

        let response_ip = &response[response.len() - 4..];
        assert_eq!(response_ip, &[6, 6, 6, 6]);
    }
}
