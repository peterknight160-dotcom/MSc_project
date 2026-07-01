// Implement the receiver
#[macro_use]
mod my_macros;

use core_utils_tokio::*;
use kyber::{ML_KEM_512, MlKemCiphertext, MlKemKeyPair};
//use serde::{Deserialize, Serialize};
use ::std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const RECEIVER_ADDR: &str = "127.0.0.1:8090";
const RECEIVER_ADDR_CONTROL: &str = "127.0.0.1:8095";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Step 2
    let signature_keys = match get_keys_from_control(RECEIVER_ADDR_CONTROL).await {
        Ok(v) => v,
        Err(_) => panic!("Failed to get keys from controller, exiting"),
    };
    let signature_keys = Arc::new(signature_keys);

    println!("Have both keys, ready to rock and roll");

    // Main receiver loop

    let listener = TcpListener::bind(RECEIVER_ADDR).await?;
    println!("Echo server running on {}", RECEIVER_ADDR);

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);

        let signature_keys = Arc::clone(&signature_keys);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, signature_keys).await {
                eprintln!("Error handling {}: {}", addr, e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    mut socket: TcpStream,
    signature_keys: Arc<SignatureKeys>,
) -> std::io::Result<()> {
    let mut buffer = [0; 100_000];

    'fred: loop {
        // Step 3  - Get connection request from client
        let bytes_read = socket.read(&mut buffer).await?;

        let received = received_string!(buffer, bytes_read);

        let s = receive_signed_rq(&signature_keys, received).await;

        // Step 4 = Send ml_key_to_send to client
        //
        let key_pair = MlKemKeyPair::generate(ML_KEM_512).unwrap();
        let s = ml_key_to_send(&signature_keys, &key_pair)?;
        socket.write_all(s.as_bytes()).await?;

        // Step 5  - Receive ciphertext from client and decapsulate to get shared secret

        let bytes_read = socket.read(&mut buffer).await?;
        let received = received_string!(buffer, bytes_read);

        let ss_receiver = get_ss_from_ct(&buffer[..bytes_read], &key_pair).unwrap();

        println!("Shared Secret is {:?}", ss_receiver.as_bytes());

        'inner: loop {
            let bytes_read = socket.read(&mut buffer).await?;

            let received = received_string!(buffer, bytes_read);

            let s = receive_message(ss_receiver.as_bytes(), received);

            match s {
                Ok(msg) => {
                    println!("Got message: {}", msg);
                    if msg == "END" {
                        println!("Received END message, closing connection.");
                        break 'fred;
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving message: {}", e);
                    break 'fred;
                }
            }
            
        }
    }

    Ok(())
}
