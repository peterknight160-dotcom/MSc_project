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
use tokio_postgres::NoTls;

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
    let (client, connection) = tokio_postgres::connect(
        "host=localhost user=vehicle password=obdvehicle port=5468 dbname=demo_odb",
        NoTls,
    )
    .await
    .map_err(|e| {
        eprintln!("Failed to connect to the database: {}", e);
        Error::new(ErrorKind::Other, "Database connection failed")
    })?;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });
    let client = Arc::new(client);

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
                let value = client.clone();
                tokio::spawn(async move {

                    if let Err(e) = handle_connection(socket, signature_keys, tx,nonces, Arc::clone(&value)).await {
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
    client: Arc<tokio_postgres::Client>,
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
            let _ = log_authentication_to_database(
                Arc::clone(&client),
                "Unknown",
                "receive_signed_rq - Permission denied",
            )
            .await;
            //end the connection
            return Err(Error::new(ErrorKind::PermissionDenied, "Permission denied"));
        }
        Err(e) => {
            let message = format!("receive_signed_rq - Other error: {}", e);
            let _ = log_authentication_to_database(Arc::clone(&client), "Unknown", &message).await;
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

    let _ = log_authentication_to_database(
        Arc::clone(&client),
        "Unknown",
        "Client authenticated successfully, shared secret established  ",
    )
    .await;

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
            Ok(msg) => {
                let td = check_message(&msg, Arc::clone(&nonces)).await;
                match td {
                    Ok(telemetry_data) => {
                        println!("Telemetry data: {:?}", telemetry_data);
                        let _ = log_authentication_to_database(
                            Arc::clone(&client),
                            telemetry_data.vehicle_id.as_deref().unwrap_or("Unknown"),
                            "Telemetry data received successfully",
                        )
                        .await;
                        // Step 6 - save the message to the database - currently the epoch, the speed value and units and the vehicle id

                        if telemetry_data.vehicle_id == Some("END".to_string()) {
                            println!("Received END message, closing connection.");
                            let _ = tx.send(()).await;
                            return Ok(());
                        }
                        // Log message to database
                        log_message_to_database(Arc::clone(&client), &telemetry_data).await?;
                        println!(
                            "Vehicle ID: {}",
                            telemetry_data.vehicle_id.as_ref().unwrap()
                        );
                        println!(
                            "Speed: {} ({})",
                            telemetry_data.speed.as_ref().unwrap().value,
                            telemetry_data.speed.as_ref().unwrap().unit
                        );

                        let date_time = chrono::DateTime::from_timestamp(
                            telemetry_data.epoch.unwrap() as i64,
                            0,
                        )
                        .unwrap();

                        println!("Date and Time: {}", date_time);
                        println!("Epoch: {:?}\n", telemetry_data.epoch.as_ref().unwrap());
                    }
                    Err(e) => {
                        eprintln!("Error checking message: {}", e);
                        let _ = log_authentication_to_database(
                            Arc::clone(&client),
                            "Unknown",
                            &format!("Error checking message: {}", e),
                        )
                        .await;
                        let _ = tx.send(()).await;
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("Error checking message: {}", e),
                        ));
                    }
                }
                // Step 6 - save the message to the database - currently the epoch, the speed value and units and the vehicle id
            }
            Err(e) => {
                eprintln!("Error receiving message: {}", e);
                let _ = log_authentication_to_database(
                    Arc::clone(&client),
                    "Unknown",
                    &format!("Error receiving message: {}", e),
                )
                .await;
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

    let timestamp = &msg[28..40];
    //Times is 12 characters long, use base65 to decode the timestamp to an array of bytes, then convert to a epoch time in seconds
    let timestamp_decoded = return_time_as_millis_from_base64(timestamp);

    println!("Decoded timestamp: {}", timestamp_decoded);
    // Return if end
    let end = &msg[40..43];
    if end == "END" {
        return Ok(VehicleTelemetryData {
            speed: Some(Measurement {
                value: 0.0,
                unit: "N/A".to_string(),
            }),
            vehicle_id: Some("END".to_string()),
            epoch: Some(0),
        });
    }
     match check_timestamp(&timestamp_decoded).await {
        Ok(()) => {
            ();
        }
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Timestamp check failed: {}", e),
            ));
        }
    } 

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
    let data = get_values_from_json(&msg[40..]).await.unwrap();
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
