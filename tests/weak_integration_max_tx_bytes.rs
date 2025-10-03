// Test for max_tx_bytes feature
// Separated into its own file for clarity

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[test]
fn test_max_tx_bytes_limits_request_upload() {
    // Track received bytes on the backend server
    let received_bytes = Arc::new(Mutex::new(0usize));
    let received_bytes_clone = received_bytes.clone();

    // Start a simple HTTP backend server that counts received bytes
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
    let backend_port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut total_bytes = 0usize;

            // Read request line
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                total_bytes += line.len();
            }

            // Read headers and count Content-Length if present
            let mut content_length = 0usize;
            loop {
                line.clear();
                if reader.read_line(&mut line).is_ok() {
                    total_bytes += line.len();
                    if line.starts_with("Content-Length:")
                        && let Some(len_str) = line.split(':').nth(1)
                    {
                        content_length = len_str.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" {
                        break;
                    }
                } else {
                    break;
                }
            }

            // Read body
            if content_length > 0 {
                let mut body_buf = vec![0u8; content_length];
                if let Ok(n) = std::io::Read::read(&mut reader, &mut body_buf) {
                    total_bytes += n;
                }
            }

            *received_bytes_clone.lock().unwrap() = total_bytes;

            // Send response
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            let _ = stream.write_all(response.as_bytes());
        }
    });

    // Give backend server time to start
    thread::sleep(Duration::from_millis(100));

    // Start httpjail in server mode with max_tx_bytes limit
    // Note: We use server mode and send HTTP request directly to avoid curl's localhost proxy bypass behavior
    let httpjail_path: &str = env!("CARGO_BIN_EXE_httpjail");
    let proxy_port = 18080u16; // Use a specific port for this test
    let mut httpjail = Command::new(httpjail_path)
        .arg("--server")
        .arg("--js")
        .arg("({allow: {max_tx_bytes: 1024}})")
        .env("HTTPJAIL_HTTP_BIND", proxy_port.to_string())
        .env("HTTPJAIL_SKIP_KEYCHAIN_INSTALL", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start httpjail server");

    // Wait for httpjail to start listening
    let mut connected = false;
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));

        // Check if process exited
        if let Ok(Some(status)) = httpjail.try_wait() {
            let mut stderr = httpjail.stderr.take().unwrap();
            let mut stderr_content = String::new();
            let _ = std::io::Read::read_to_string(&mut stderr, &mut stderr_content);
            panic!(
                "httpjail server exited early with status: {}\nStderr: {}",
                status, stderr_content
            );
        }

        // Try to connect
        if TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).is_ok() {
            connected = true;
            break;
        }
    }

    if !connected {
        let _ = httpjail.kill();
        panic!(
            "httpjail server did not start listening on port {} within 2 seconds",
            proxy_port
        );
    }

    // Send HTTP request directly to httpjail proxy with large body (5KB)
    let large_body = "X".repeat(5000);
    let request = format!(
        "POST http://127.0.0.1:{}/upload HTTP/1.1\r\n\
         Host: 127.0.0.1:{}\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        backend_port,
        backend_port,
        large_body.len(),
        large_body
    );

    // Connect directly to httpjail proxy and send the request
    let mut proxy_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .expect("Failed to connect to httpjail proxy");
    proxy_stream
        .write_all(request.as_bytes())
        .expect("Failed to write request");

    // Read response
    let mut response = Vec::new();
    let mut reader = BufReader::new(proxy_stream);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).is_ok() && !line.is_empty() {
            response.extend_from_slice(line.as_bytes());
            if line == "\r\n" {
                break;
            }
        } else {
            break;
        }
    }

    // Kill httpjail server
    let _ = httpjail.kill();
    let _ = httpjail.wait();

    // Wait for backend server to finish
    let _ = server_handle.join();

    let bytes_received = *received_bytes.lock().unwrap();
    println!("Backend server received: {} bytes", bytes_received);
    println!("Response: {}", String::from_utf8_lossy(&response));

    // Backend server should have received <= 1024 bytes (including headers + body)
    assert!(
        bytes_received <= 1024,
        "Backend should receive at most 1024 bytes, but received {} bytes",
        bytes_received
    );

    // Backend server should have received some data (not zero)
    assert!(bytes_received > 0, "Backend should have received some data");
}
