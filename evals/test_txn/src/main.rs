use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();

    let msg = "Hello, UTF-8: héllo 🌍\n";
    stream.write_all(msg.as_bytes()).unwrap();
    let mut buffer = [0; 1024];

    // Read data from the stream
    /* match stream.read(&mut buffer) {
        Ok(bytes_read) => {
            if bytes_read > 0 {
                let received = String::from_utf8_lossy(&buffer[..bytes_read]);
                println!("Received: {}", received);
            }
        }
        Err(e) => eprintln!("Failed to read from connection: {}", e),
    } */
    println!( "Got here");
    stream.write_all(b"hello world\n").unwrap();
    println!( "Got here2");
}
