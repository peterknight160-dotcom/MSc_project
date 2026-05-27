use std::net::TcpStream;
use std::io::Write;

fn main() {
    let mut stream = TcpStream::connect("127.0.0.1:8080").unwrap();
    
    let msg = "Hello, UTF-8: héllo 🌍\n";
    stream.write_all(msg.as_bytes()).unwrap();

    stream.write_all(b"hello world\n").unwrap();
}