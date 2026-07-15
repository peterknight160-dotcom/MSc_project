// Implement the receiver

use base65::{self, base64_to_bytes};
use core_utils_tokio::*;
use kyber::{ML_KEM_512, MlKemKeyPair};

//use std::collections:: HashSet;

use std::io::{Error, ErrorKind};
use std::time::SystemTime;
//use std::result;
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
    let nonces = Arc::new(tokio::sync::Mutex::new(0u64));

    println!("Have both keys, ready to rock and roll");

    // Main receiver loop
 

 

    let listener_result = TcpListener::bind(RECEIVER_ADDR).await;
    if listener_result.is_err() {
        eprintln!(
            "Failed to bind to {}: {}",
            RECEIVER_ADDR,
            listener_result.unwrap_err()
        );
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to bind to receiver address",
        ));
    }
    let listener = listener_result.unwrap();
    println!("Echo server running on {}", RECEIVER_ADDR);

    let (tx, mut rx) = mpsc::channel::<()>(1);

    loop {
        let nonces = Arc::clone(&nonces);
        println!("Nonces before select: {:?}", nonces.lock().await);
        tokio::select! {
            _ = rx.recv() => {
                println!("Shutdown requested");
                break Ok(());
            }

            Ok((socket, addr)) = listener.accept() => {
                let signature_keys = Arc::clone(&signature_keys);
                let tx = tx.clone();
        
                tokio::spawn(async move {

                    if let Err(e) = handle_connection(socket, signature_keys, tx,nonces).await {
                        eprintln!("Error handling {}: {}", addr, e);
                    }
                });
            }
        }
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    signature_keys: Arc<SignatureKeys>,
    tx: mpsc::Sender<()>,
    nonces: Arc<tokio::sync::Mutex<u64>>,
  
) -> std::io::Result<()> {
    // Step 3  - Get connection request from client
    let len = socket.read_u32().await?;

    let mut buffer = vec![0; len as usize];
    let _bytes_read = socket.read_exact(&mut buffer).await?;

    //let received = received_string!(buffer, bytes_read);

    // let s = receive_signed_rq(&signature_keys, &buffer).await;

    match receive_signed_rq(&signature_keys, &buffer).await {
        Ok(text) => println!("{text}"),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
        
            //end the connection
            return Err(Error::new(ErrorKind::PermissionDenied, "Permission denied"));
        }
        Err(e) => {
            let message = format!("receive_signed_rq - Other error: {}", e);
          
        }
    }

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

    

    println!(
        "Shared Secret is {:?}",
        base65::base64_from_bytes(ss_receiver.as_bytes()).unwrap()
    );

    loop {
        let len = socket.read_u32().await?;
        let mut buffer = vec![0; len as usize];
        let _bytes_read = socket.read_exact(&mut buffer).await?;

        //let received = received_string!(buffer, bytes_read);

        let s = receive_message(ss_receiver.as_bytes(), &buffer);

        match s {
            Ok(msg) => (),
            
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
          
                let _ = tx.send(()).await;
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Error receiving message: {}", e),
                ));
            }
        }
    }
}



pub async fn check_nonce(
    nonce_u64: &u64,
    nonces: Arc<tokio::sync::Mutex<u64>>,
) -> std::io::Result<()> {
    let mut largest_nonce = nonces.lock().await;
    if *largest_nonce >= *nonce_u64 {
        return Err(Error::new(ErrorKind::Other, "Nonce has already been used"));
    }
    *largest_nonce = *nonce_u64;

    Ok(())
}

/* pub async fn get_values_from_json(json: &str) -> std::io::Result<VehicleTelemetry> {
    let telemetry: VehicleTelemetry = serde_json::from_str(json).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Failed to deserialize JSON: {}", e),
        )
    })?;
    Ok(telemetry)
} */

pub async fn check_timestamp(timestamp: &u128) -> std::io::Result<()> {
    // Get the current time in seconds since the epoch
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i128;
    if (*timestamp as i128 - current_time).abs() > 10000 {
        return Err(Error::new(
            ErrorKind::Other,
            "Timestamp is not within 10 seconds of current time",
        ));
    }

    Ok(())
}

pub async fn get_values_from_json(json: &str) -> Result<VehicleTelemetry, serde_json::Error> {
    serde_json::from_str(json)
}
