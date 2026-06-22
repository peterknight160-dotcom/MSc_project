use std::io::{Read};
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    // Bind to address and port (e.g., 127.0.0.1:8080)
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("Listening on 127.0.0.1:8080...");

    // Accept incoming connections
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("New connection from: {}", stream.peer_addr()?);

                let mut buffer = [0; 1024];

                // Read data from the stream
                match stream.read(&mut buffer) {
                    Ok(bytes_read) => {
                        if bytes_read > 0 {
                            let received = String::from_utf8_lossy(&buffer[..bytes_read]);
                            println!("Received: {}", received);
                        }
                    }
                    Err(e) => eprintln!("Failed to read from connection: {}", e),
                }
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }

    Ok(())
}