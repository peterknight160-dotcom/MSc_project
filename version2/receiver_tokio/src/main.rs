// Implement the receiver


use core_utils_tokio::*;
use base65::{self, base64_to_bytes};
use kyber::{ML_KEM_512,  MlKemKeyPair};


//use std::collections:: HashSet;


use std::io::{ Error, ErrorKind };
//use std::result;
//use serde::{Deserialize, Serialize};
use ::std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const RECEIVER_ADDR: &str = "127.0.0.1:8090";
const RECEIVER_ADDR_CONTROL: &str = "127.0.0.1:8095";

use receiver_tokio::VehicleTelemetry;

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
            let _bytes_read = socket.read_exact(&mut buffer).await?;

            //let received = received_string!(buffer, bytes_read);



            let s = receive_message(ss_receiver.as_bytes(), &buffer);

            match s {
                Ok(msg) => {
                    let text = check_message( &msg, Arc::clone(&nonces)).await?;
                    // Step 6 - save the message to the database - currently the epoch, the speed value and units and the vehicle id

                    println!("Received message: {}", text);
                    if text == "END" {
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

pub async fn check_message(msg: &str, nonces: Arc<tokio::sync::Mutex<u64>>) -> std::io::Result<String> {
    //println!("Received message: {}", msg);
    // Split off the nonce and timestamp from the message
    // Nonce is 28 characters long, timestamp is 12 characters long
    let nonce = &msg[..28];
    // use base65 to decode the nonce 
    let nonce_decoded = String::from_utf8(base64_to_bytes(nonce).unwrap()).unwrap();
 
    let nonce_u64 = nonce_decoded.parse::<u64>().unwrap();
   
  
    let _timestamp = &msg[28..40];   
    // Return if end
    let end = &msg[40..43];
    if end == "END" {
        return Ok("END".to_string());
    }
    let data = get_values_from_json(&msg[40..]).await.unwrap()  ;
    match check_nonce(&nonce_u64, Arc::clone(&nonces)).await {
        Ok(()) => {
          ();
        }
        Err(e) => {
          return Err(Error::new(
                ErrorKind::Other,
                format!("Nonce check failed: {}", e),
            ));
        }
    }

    let speed = match data.speed {
        Some(ref s) => format!("{} {}", s.value, s.unit),
        None => "N/A".to_string(),
    };
    let vehicle_id = match data.vehicle_id {
        Some(ref v) => v.clone(),
        None => "N/A".to_string(),
    };
    let epoch = match data.epoch {
        Some(e) => e,
        None => 0u64,
    };



    

    
    let return_val = format!(
        "Speed: {}, Vehicle ID: {}, Epoch: {}",
        speed, vehicle_id, epoch
    );
    
    Ok(return_val)
}

pub async  fn check_nonce(nonce_u64: &u64, nonces: Arc<tokio::sync::Mutex<u64>>) -> std::io::Result<()> {
    let mut largest_nonce = nonces.lock().await;
    if *largest_nonce >= *nonce_u64 {
        return Err(Error::new(
            ErrorKind::Other,
            "Nonce has already been used",
        ));
    }
    *largest_nonce = *nonce_u64;
 
    Ok(())
}

pub async fn get_values_from_json ( json: &str) -> std::io::Result<VehicleTelemetry> {  
    let telemetry: VehicleTelemetry = serde_json::from_str(json).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Failed to deserialize JSON: {}", e),
        )
    })?;
    Ok(telemetry)
}