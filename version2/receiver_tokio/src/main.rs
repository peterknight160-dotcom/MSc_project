// Implement the receiver


use core_utils_tokio::*;
use kyber::{ML_KEM_512,  MlKemKeyPair};


use std::io::{ Error, ErrorKind };
//use serde::{Deserialize, Serialize};
use ::std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

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
    
    let listener_result = TcpListener::bind(RECEIVER_ADDR).await;
    if listener_result.is_err() {
        eprintln!("Failed to bind to {}: {}", RECEIVER_ADDR, listener_result.unwrap_err());
        return Err(Error::new(
                ErrorKind::Other,
                "Authorisation Failed in receive_signed_rq ",
            ))
    }
    let listener = listener_result.unwrap();
    println!("Echo server running on {}", RECEIVER_ADDR);

    
let (tx, mut rx) = mpsc::channel::<()>(1);

loop {
    tokio::select! {
        _ = rx.recv() => {
            println!("Shutdown requested");
            break Ok(());
        }

        Ok((socket, addr)) = listener.accept() => {
            let signature_keys = Arc::clone(&signature_keys);
            let tx = tx.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, signature_keys, tx).await {
                    eprintln!("Error handling {}: {}", addr, e);
                }
            });
        }
    }
}

    
/*     loop {
        
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);

        let signature_keys = Arc::clone(&signature_keys);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, signature_keys).await {
                eprintln!("Error handling {}: {}", addr, e);
            }
        });
    } */
 
 
}

async fn handle_connection(
    mut socket: TcpStream,
    signature_keys: Arc<SignatureKeys>,
    tx: mpsc::Sender<()>,
) -> std::io::Result<()> {
    

    'fred: loop {
        // Step 3  - Get connection request from client
        let len = socket.read_u32().await?;
        
        let mut buffer = vec![0; len as usize];
        let _bytes_read = socket.read_exact(&mut buffer).await?;

        //let received = received_string!(buffer, bytes_read);

        let _s = receive_signed_rq(&signature_keys, &buffer).await;

        // Step 4 = Send ml_key_to_send to client
        //
        let key_pair = MlKemKeyPair::generate(ML_KEM_512).unwrap();
        let s = ml_key_to_send(&signature_keys, &key_pair)?;
        socket.write_u32(s.len() as u32).await?;
        socket.write_all(&s).await?;

        // Step 5  - Receive ciphertext from client and decapsulate to get shared secret

        let len = socket.read_u32().await?;
        let mut buffer = vec![0; len as usize];
        let bytes_read = socket.read_exact(&mut buffer).await?;
        //let received = received_string!(buffer, bytes_read);

        let ss_receiver = get_ss_from_ct(&buffer[..bytes_read], &key_pair).unwrap();

        println!("Shared Secret is {:?}", ss_receiver.as_bytes());

         loop {
            let len = socket.read_u32().await?;
            let mut buffer = vec![0; len as usize];
            let bytes_read = socket.read_exact(&mut buffer).await?;

            //let received = received_string!(buffer, bytes_read);



            let s = receive_message(ss_receiver.as_bytes(), &buffer);

            match s {
                Ok(msg) => {
                    println!("Got message: {}", msg);
                    if msg == "END" {
                        println!("Received END message, closing connection.");
                        let _ = tx.send(()).await;
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
