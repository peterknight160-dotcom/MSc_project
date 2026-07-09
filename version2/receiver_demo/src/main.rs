// Implement the receiver

use base65::{self, base64_to_bytes};
use core_utils_tokio::*;
use kyber::{ML_KEM_512, MlKemKeyPair};

//use std::collections:: HashSet;

use std::io::{Error, ErrorKind};
//use std::result;
//use serde::{Deserialize, Serialize};
use ::std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
//use tokio_postgres::{NoTls, Error as PgError};

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
   

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
   



    let listener_result = TcpListener::bind(RECEIVER_ADDR).await;
    if listener_result.is_err() {
        eprintln!(
            "Failed to bind to {}: {}",
            RECEIVER_ADDR,
            listener_result.unwrap_err()
        );
        return Err(Error::new(
            ErrorKind::Other,
            "Authorisation Failed in receive_signed_rq ",
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
                    let telemetry_data = check_message(&msg, Arc::clone(&nonces)).await?;
                    // Step 6 - save the message to the database - currently the epoch, the speed value and units and the vehicle id

             
                    if telemetry_data.vehicle_id == Some("END".to_string()) {
                        println!("Received END message, closing connection.");
                        let _ = tx.send(()).await;
                        return  Ok(());
                    }
                    // Log message to database
                    //log_message_to_database(Arc::clone(&client), &telemetry_data).await?;
                    // print the message
                    println!("Vehicle ID: {:?}", telemetry_data.vehicle_id.as_ref().unwrap ());
                    println!("Speed: {}, {} ", telemetry_data.speed.as_ref().unwrap().value, telemetry_data.speed.as_ref().unwrap() .unit);  
                    println!("Epoch: {:?}", telemetry_data.epoch.as_ref().unwrap());

                }
                Err(e) => {
                    eprintln!("Error receiving message: {}", e);
                    // Return an error to the client and close the connection
                    let _ = tx.send(()).await;
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Error receiving message: {}", e),
                    ));
                    
                }
            }
        }
    

 
}

pub async fn check_message(
    msg: &str,
    nonces: Arc<tokio::sync::Mutex<u64>>,
) -> std::io::Result<VehicleTelemetryData> {
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
        return Ok(VehicleTelemetryData {
        speed: Some(Measurement { value: 0.0, unit: "N/A".to_string() }),
        vehicle_id: Some("END".to_string()),
        epoch: Some(0),})
    }   
    
    
    let data = get_values_from_json(&msg[40..]).await.unwrap();
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



   
    Ok(VehicleTelemetryData {
        speed: data.speed,
        vehicle_id: data.vehicle_id,
        epoch: data.epoch,
    })
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




pub async fn get_values_from_json(
    json: &str,
) -> Result<VehicleTelemetry, serde_json::Error> {
    serde_json::from_str(json)
}
