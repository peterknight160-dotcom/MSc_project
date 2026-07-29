//use base65::*;
use core_utils_classic::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";
//const JSON_FILE: &str = "JSON.csv";
//use client_auth_classic::{CsvReader, json_doc_from_reader};

use ed25519_dalek::{ SigningKey,VerifyingKey};
use x25519_dalek::{EphemeralSecret, PublicKey};
use getrandom::{SysRng, rand_core::UnwrapErr};

use std::io::{self};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;

#[cfg(feature = "trace")]
macro_rules! trace {
    ($($arg:tt)*) => {
        println!($($arg)*);
    };
}

#[cfg(not(feature = "trace"))]
macro_rules! trace {
    ($($arg:tt)*) => {};
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    
       let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        println!("\n\n\n Usage: {} <client_addr> <receiver_addr> <receiver_addr_control>", args[0]);
        println!("Example: {} 127.0.0.1:8080 127.0.0.1:8090 127.0.0.1:8095\n\n\n", args[0]);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid number of arguments",
        ));
    }

        let client_addr = &args[1];
    let receiver_addr = &args[2];
    let _receiver_addr_control = &args[3];
    
        // Step 1
    let signature_keys = match get_keys_from_control(client_addr).await {
        Ok(v) => v,
        Err(e) => panic!(" Have not got a valid signature_keys, {}", e),
    };
    // Now do stuff with them

    println!("Have both keys, ready to rock and roll");

       println!("Have both keys, ready to rock and roll");

    // Sleep for a second to allow the receiver to start up
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Now to do the performance test

    let eloops = std::env::var("LOOPS").ok(); //Get result and convert option
    let nloops: u32;

    match eloops.is_some() {
        true => nloops = eloops.unwrap().parse::<u32>().unwrap(),
        false => nloops = 10,
    }

    let mut auth_time_hash: BTreeMap<u128, u32> = BTreeMap::new();

      for i in 0..nloops+10 {
          let start_encrypt = Instant::now();
        let mut stream = TcpStream::connect(receiver_addr).await?;

   

    //Step 3

    //println!("Commence authentication with the receiver");

    let _s = match send_signed_rq(&signature_keys, &mut stream).await {
        Ok(v) => v,
        Err(_) => panic!("Failed to send keys, exiting"),
    };

    //Step 4

    //let s = get_ml_keys(&signature_keys, &mut stream).await;
    let pub_key = get_ec25519_keys(&signature_keys, &mut stream).await.unwrap();

    //println!("Got the EC25519 Key from the receiver, ready to compute ciphertext and shared secret");

    //Step 5

    // Generate EC25519 key pair for the sender

    let sender_secret = EphemeralSecret::random_from_rng( &mut UnwrapErr(SysRng));
    let sender_public = PublicKey::from(&sender_secret);
    
    let s = ec25519_key_to_send(&signature_keys, &sender_public)?;
    stream.write_u32(s.len() as u32).await?;
    stream.write_all(&s).await?;
    trace!("[Client 96] Length of key set to send to receiver: {:?}", s.len());


    let shared_secret = sender_secret.diffie_hellman(&pub_key) ;

  

    

    //println!("Shared Secret is {:?}", base65::base64_from_bytes(shared_secret.as_bytes()).unwrap());
            let auth_time = start_encrypt.elapsed().as_micros();
         
        //println!("Auth time: {} microseconds", auth_time);
        if i >= 10 {
            *auth_time_hash.entry(auth_time).or_insert(0) += 1;
        }
        

        // Disconnect from the receiver
        let _ = stream.shutdown().await;
    }

        let stats_auth = stats_from_btree(&auth_time_hash, "ED25519 Authentication");
    // Get mean + 2 std devs
    let twosigma = stats_auth.mean + 2.0 * stats_auth.std_dev;

    let _ = draw_histogram_from_btree(&auth_time_hash, "ED25519_Authentication", twosigma);
    println!(        "Stats {} ",stats_auth           );
  
    Ok(())
}

/* fn get_input(prompt: &str) -> String {
    let mut input = String::new();
    println!("{}", prompt);

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    // Remove any trailing whitespace
    input.trim_end().to_string()
}

async fn send(input: String, aes_key: &[u8], nonce: &u64, stream: &mut TcpStream) {
    // Add nonce and timestamp to the input
    // Format nonce as 20-digit zero-padded string

    let nonce_str = base64_from_str(&format!("{:020}", nonce)).unwrap();
    let timestmp = get_time_as_millis_base64();
    let input_with_nonce_and_timestamp = nonce_str + &timestmp + &input;
    //println!("Sending input: {}", input_with_nonce_and_timestamp);
    let _ = receive_send_ready(input_with_nonce_and_timestamp, aes_key, stream).await;
} */
