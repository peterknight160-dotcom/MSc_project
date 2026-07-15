//use base65::*;
use core_utils_pqc::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";
//const JSON_FILE: &str = "JSON.csv";
use client_auth_pqc::{CsvReader, json_doc_from_reader};
use kyber::ML_KEM_512;

use tokio::net::{TcpStream};
use tokio::io::{AsyncWriteExt};

use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Step 1
    let signature_keys = match get_keys_from_control(ADDR).await {
        Ok(v) => v,
        Err(e) => panic!(" Have not got a valid signature_keys, {}", e),
    };
    // Now do stuff with them

    println!("Have both keys, ready to rock and roll");

    // Now to do the performance test

    let eloops = env::var("LOOPS").ok(); //Get result and convert option
    let nloops: u32;

    match eloops.is_some() {
        true => nloops = eloops.unwrap().parse::<u32>().unwrap(),
        false => nloops = 10,
    }

    let mut auth_time_hash: BTreeMap<u128, u32> = BTreeMap::new();

    for _ in 0..nloops {
          let start_encrypt = Instant::now();
        let mut stream = TcpStream::connect(RECEIVER_ADDR).await?;

        //Step 3

        println!("Commence authentication with the receiver");

        let _s = match send_signed_rq(&signature_keys, &mut stream).await {
            Ok(v) => v,
            Err(_) => panic!("Failed to send keys, exiting"),
        };

        //Step 4

        //let s = get_ml_keys(&signature_keys, &mut stream).await;
        let pub_key = get_ml_keys(&signature_keys, &mut stream).await.unwrap();

        println!("Got the ML Key from the receiver, ready to compute ciphertext and shared secret");

        //Step 5

        let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_512, pub_key.as_slice()).unwrap();
        let shared_secret = ss_sender.as_bytes();

        let s = send_ciphertext(ct, &mut stream).await;
        if s.is_ok() {
            println!("Got {}", s.unwrap());
        }

        let auth_time = start_encrypt.elapsed().as_micros();
        *auth_time_hash.entry(auth_time).or_insert(0) += 1;

        // Disconnect from the receiver
        let _ = stream.shutdown().await;
    }

        let stats_auth = stats_from_btree(&auth_time_hash, "PQC Authentication");
    // Get mean + 2 std devs
    let twosigma = stats_auth.mean + 2.0 * stats_auth.std_dev;

    let _ = draw_histogram_from_btree(&auth_time_hash, "PQC_Authentication", twosigma);
    println!(        "Stats {} ",stats_auth           );

    Ok(())
}


