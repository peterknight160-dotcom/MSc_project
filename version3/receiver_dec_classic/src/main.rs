// Implement the receiver

use base65::*;

use core_utils_classic::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey}; // Used for signing and verifying messages
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use x25519_dalek::{EphemeralSecret, PublicKey}; // Used for key exchange

use getrandom::{SysRng, rand_core::UnwrapErr};

//use std::collections:: HashSet;

use std::io::{Error, ErrorKind};
use std::time::SystemTime;
use useful_stats::*;
use std::collections::BTreeMap;
use std::time::Instant;

//use std::result;
//use serde::{Deserialize, Serialize};
use ::std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

//const RECEIVER_ADDR: &str = "127.0.0.1:8090";
//const RECEIVER_ADDR_CONTROL: &str = "127.0.0.1:8095";

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Get the two addreess from the command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        println!(
            "\n\n\n Usage: {} <client_addr> <receiver_addr> <receiver_addr_control>",
            args[0]
        );
        println!(
            "Example: {} 127.0.0.1:8080 127.0.0.1:8090 127.0.0.1:8095\n\n\n",
            args[0]
        );
        return Err(Error::new(ErrorKind::Other, "Invalid number of arguments"));
    }

    let _client_addr = &args[1];
    let receiver_addr = &args[2];
    let receiver_addr_control = &args[3];

    // Get the array of keys  from the text file
    // signature_keys is a vector of 256 bit keys (a vector of bytes), which can be used to verify signatures on messages
    let mut signature_keys: Vec<Arc<Vec<u8>>> = Vec::new();
    if let Ok(lines) = read_lines("./keys_generated.txt") {
        // Consumes the iterator, returns an (Optional) String
        for line in lines.map_while(Result::ok) {
            let key = base64_to_bytes(&line).unwrap();

            signature_keys.push(Arc::new(key));
        }
    }
    // Signature keys contains a list of 256  bit keys, which can be iterated around, or not

    println!("Got {} signature keys from the file", signature_keys.len());

    let shared_secret = Arc::clone(&signature_keys[0]); // For now, just use the first key in the list

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

    let (tx, mut rx) = mpsc::channel::<()>(1);

    loop {
        //let shared_secret = Arc::new(shared_secret) ;
        //println!("Nonces before select: {:?}", nonces.lock().await);
        tokio::select! {
            _ = rx.recv() => {
                println!("Shutdown requested");
                 break Ok(());
            }

            Ok((socket, _addr)) = listener.accept() => {
                    let tx = tx.clone();


         let ss = Arc::clone(&shared_secret);
                tokio::spawn(async move {

                    if let Err(_e) = handle_connection(socket, ss, tx).await {
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
    shared_secret: Arc<Vec<u8>>,
    tx: mpsc::Sender<()>,
) -> std::io::Result<()> {
    // For this just gets a whole series of encrypted packets from the client.

    println!(
        "Shared Secret is {:?}",
        base65::base64_from_bytes(&shared_secret).unwrap()
    );


       let mut dec_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    loop {


        let len = socket.read_u32().await?;
        let mut buffer = vec![0; len as usize];
        let _bytes_read = socket.read_exact(&mut buffer).await?;

        //let received = received_string!(buffer, bytes_read);

        let start_decrypt = Instant::now();
        let ss = shared_secret.clone();

        let s = receive_message(&ss, &buffer);

        let elapsed_decrypt = start_decrypt.elapsed().as_micros();
        *dec_time_hash.entry(elapsed_decrypt).or_insert(0) += 1;
        

        match s {
            Ok(msg) => {
                
                // if msg ends with "END", then break the loop
                if msg.ends_with("END") {
                    println!("Received END message, closing connection");

                    let stats_dec = stats_from_btree(&dec_time_hash, "PQC Decryption");
                    // Get mean + 2 std devs
                    let twosigma = stats_dec.mean + 2.0 * stats_dec.std_dev;

                    let _ = draw_histogram_from_btree(&dec_time_hash, "PQC_Decryption", twosigma);
                    println!("Stats {} ", stats_dec);
                    let _ = tx.send(()).await;
                    break;
                }
                 
            }

            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Error receiving message: {}", e),
                ));
            }
        }
    }

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
