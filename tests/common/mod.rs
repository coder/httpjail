use std::net::TcpListener;
use std::io::{Read, Write};
use std::thread;

/// Simple mock HTTP server for testing
pub struct MockServer {
    pub port: u16,
    pub url: String,
}

impl MockServer {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{}", port);

        thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(mut stream) = stream {
                    let mut buffer = [0; 1024];
                    let _ = stream.read(&mut buffer);
                    
                    // Simple HTTP response
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                    let _ = stream.write_all(response.as_bytes());
                }
            }
        });

        // Give the server time to start
        thread::sleep(std::time::Duration::from_millis(100));

        MockServer { port, url }
    }
}