// Implement the receiver


use core_utils_classic::*;
use ed25519_dalek::{ SigningKey,VerifyingKey,Signer,Verifier,Signature}; // Used for signing and verifying messages
use x25519_dalek::{EphemeralSecret, PublicKey};  // Used for key exchange

use getrandom::{SysRng, rand_core::UnwrapErr};

//use std::collections:: HashSet;

use std::io::{Error, ErrorKind};
use std::time::SystemTime;
//use std::result;
//use serde::{Deserialize, Serialize};
use ::std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;


//const RECEIVER_ADDR: &str = "127.0.0.1:8090";
//const RECEIVER_ADDR_CONTROL: &str = "127.0.0.1:8095";

#[tokio::main]
async fn main() -> std::io::Result<()> {
     // Get the two addreess from the command line arguments
    let args: Vec<String> = std::env::args().collect();
      if args.len() != 4 {
        println!("\n\n\n Usage: {} <client_addr> <receiver_addr> <receiver_addr_control>", args[0]);
        println!("Example: {} 127.0.0.1:8080 127.0.0.1:8090 127.0.0.1:8095\n\n\n", args[0]);
        return Err(Error::new(
            ErrorKind::Other,
            "Invalid number of arguments",
        ));
    }

    let _client_addr = &args[1];
    let receiver_addr = &args[2];
    let receiver_addr_control = &args[3];

    // Step 2
    let signature_keys = match get_keys_from_control(receiver_addr_control).await {
        Ok(v) => v,
        Err(_) => panic!("Failed to get keys from controller, exiting"),
    };
    let signature_keys = Arc::new(signature_keys);
    let nonces = Arc::new(tokio::sync::Mutex::new(0u64));

    println!("Have both keys, ready to rock and roll");

    // Main receiver loop
 

 

    let listener_result = TcpListener::bind(receiver_addr).await;
    if listener_result.is_err() {
        eprintln!(
            "Failed to bind to {}: {}",
            receiver_addr,
            listener_result.unwrap_err()
        );
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to bind to receiver address",
        ));
    }
    let listener = listener_result.unwrap();
    //println!("Echo server running on {}", receiver_addr);

    //let (tx, mut rx) = mpsc::channel::<()>(1);

    loop {
        let nonces = Arc::clone(&nonces);
        //println!("Nonces before select: {:?}", nonces.lock().await);
        tokio::select! {
            // _ = rx.recv() => {
            //     println!("Shutdown requested");
            //     break Ok(());
            // }

            Ok((socket, _addr)) = listener.accept() => {
                let signature_keys = Arc::clone(&signature_keys);
        
        
                tokio::spawn(async move {

                    if let Err(_e) = handle_connection(socket, signature_keys, nonces).await {
                        //eprintln!("Error handling {}: {}", addr, e);
                        ()
                    }
                });
            }
        }
    }
}

async fn handle_connection(
    mut socket: TcpStream,
    signature_keys: Arc<SignatureKeys>,

    _nonces: Arc<tokio::sync::Mutex<u64>>,
  
) -> std::io::Result<()> {
    // Step 3  - Get connection request from client
    let len = socket.read_u32().await?;

    let mut buffer = vec![0; len as usize];
    let _bytes_read = socket.read_exact(&mut buffer).await?;

    //let received = received_string!(buffer, bytes_read);

    // let s = receive_signed_rq(&signature_keys, &buffer).await;

    match receive_signed_rq(&signature_keys, &buffer).await {
        Ok(text) => (),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
        
            //end the connection
            return Err(Error::new(ErrorKind::PermissionDenied, "Permission denied"));
        }
        Err(e) => {
            let _message = format!("receive_signed_rq - Other error: {}", e);
          
        }
    }

    // Step 4 = Send ml_key_to_send to client
    //
    let receiver_secret = EphemeralSecret::random_from_rng( &mut UnwrapErr(SysRng));
    let receiver_public = PublicKey::from(&receiver_secret);

  
    let s = ec25519_key_to_send(&signature_keys, &receiver_public)?;
    socket.write_u32(s.len() as u32).await?;
    socket.write_all(&s).await?;

    // Step 5  - Receive ciphertext from client and decapsulate to get shared secret

   let sender_public = get_ec25519_keys(&signature_keys, &mut socket).await?;
   // if not error, then we have the keys, now we can decapsulate to get the shared secret


    let ss_receiver = receiver_secret.diffie_hellman(&sender_public);

    

    //println!(        "Shared Secret is {:?}",        base65::base64_from_bytes(ss_receiver.as_bytes()).unwrap()    );
    // Done 
    /* loop {
        let len = socket.read_u32().await?;
        let mut buffer = vec![0; len as usize];
        let _bytes_read = socket.read_exact(&mut buffer).await?;

        //let received = received_string!(buffer, bytes_read);

        let s = receive_message(ss_receiver.as_bytes(), &buffer);

        match s {
            Ok(_msg) => (),
            
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
          
                let _ = tx.send(()).await;
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Error receiving message: {}", e),
                ));
            }
        }
    } */

    Ok(())
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
