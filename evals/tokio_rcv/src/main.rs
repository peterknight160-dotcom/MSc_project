// src/main.rs
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Echo server running on 127.0.0.1:8080");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket).await {
                eprintln!("Error handling {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; 1024];

    loop {
        let n = socket.read(&mut buf).await?;

        // convert the bytes to a string
        let received = String::from_utf8_lossy(&buf[..n]);
        // Prepend "Got: " to the received string
        let modified = format!("Got: \"{}\"", received);
        
        

        if n == 0 {
            // Connection closed
            break;
        }

        // Echo the data back
        socket.write_all(modified.as_bytes()).await?;
    }

    Ok(())
}