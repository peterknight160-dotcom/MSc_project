use base65::*;
use core_utils_tokio::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";
const JSON_FILE: &str = "JSON.txt";
//use client_tokio::{CsvReader, json_doc_from_reader};
use kyber::ML_KEM_512;

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use useful_stats::*;
use std::collections::BTreeMap;
use std::time::Instant;

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {

      // Get the three addresses from the command line arguments
    let args: Vec<String> = std::env::args().collect();
      if args.len() != 4 {
        println!("\n\n\n Usage: {} <client_addr> <receiver_addr> <receiver_addr_control>", args[0]);
        println!("Example: {} 127.0.0.1:8080 127.0.0.1:8090 127.0.0.1:8095\n\n\n", args[0]);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Invalid number of arguments",
        ));
    }

    let _client_addr = &args[1];
    let receiver_addr = &args[2];
    let _receiver_addr_control = &args[3];

     // This program just loops around sending the message to the receiver, waiting for the acknowledgment and recording the time



    // Get the array of keys  from the text file 
        let mut signature_keys = Vec::new();
   if let Ok(lines) = read_lines("./keys_generated.txt") {
        // Consumes the iterator, returns an (Optional) String
        for line in lines.map_while(Result::ok) {
            let key = base64_to_bytes(&line).unwrap();
                        
            signature_keys.push(key);
            
        }
    }
   // Signature keys contains a list of 256  bit keys, which can be iterated around, or not

   println! ("Got {} signature keys from the file", signature_keys.len());

   let shared_secret = &signature_keys[0]; // For now, just use the first key in the list
  

      // Connect to the receiver
    let mut stream = TcpStream::connect(receiver_addr).await?;
    println!("Connected to receiver at {}", receiver_addr);

    // Get the input from the user
    // Get array of JSON documents from the JSON.txt file

   // Get array of JSON documents from the JSON.txt file

    // Open the file in read-only mode (ignoring errors).

    let mut jsons= Vec::new();
    let file = File::open(JSON_FILE).expect("Could not open JSON.txt file");
    
    let lines = io::BufReader::new(file).lines();
    for line in lines {
        if let Ok(json_doc) = line {
            println!("JSON Document: {}", json_doc);
            jsons.push(json_doc);
        }
    }

    let eloops = env::var("LOOPS").ok(); //Get result and convert option
    let nloops: u32;

    match eloops.is_some() {
        true => nloops = eloops.unwrap().parse::<u32>().unwrap(),
        false => nloops = 10,
    }

    let mut enc_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    
    
    let mut nonce: u64 = 0;
    let mut i: usize = 0;
    for _ in 0..nloops {    

         let start_encrypt = Instant::now();

         for _ in 0..100{ 
        /* let input =
            get_input("What would you like to send a JSON to the receiver? (Type END to finish)")
                .to_uppercase(); */
        nonce += 1;
        
        // 
        let json_doc_to_send = &jsons[i];
        i = (i + 1) % jsons.len();
        send(json_doc_to_send, shared_secret, &nonce, &mut stream).await;
         }
      /*   match input.as_str() {
            "END" => break,
            "YES" | "Y" => send(json_doc_to_send, shared_secret, &nonce, &mut stream).await,
            _ => (),
        }; */
        let elapsed_encrypt = start_encrypt.elapsed().as_millis();
        *enc_time_hash.entry(elapsed_encrypt).or_insert(0) += 1;
    }
    send("END", shared_secret, &nonce, &mut stream).await;

     let stats_enc = stats_from_btree(&enc_time_hash, "PQC Encryption");
    // Get mean + 2 std devs
    let twosigma = stats_enc.mean + 2.0 * stats_enc.std_dev;

    let _ = draw_histogram_from_btree(&enc_time_hash, "PQC_Encryption", twosigma);
    println!(        "Stats {} ",stats_enc           );

    
    Ok(())
}

fn get_input(prompt: &str) -> String {
    let mut input = String::new();
    println!("{}", prompt);

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    // Remove any trailing whitespace
    input.trim_end().to_string()
}

async fn send(input: &str , aes_key: &[u8], nonce: &u64, stream: &mut TcpStream) {
    // Add nonce and timestamp to the input
    // Format nonce as 20-digit zero-padded string

    let nonce_str = base64_from_str(&format!("{:020}", nonce)).unwrap();
    let timestmp = get_time_as_millis_base64();
    let input_with_nonce_and_timestamp = nonce_str + &timestmp + input;
    //println!("Sending input: {}", input_with_nonce_and_timestamp);
    let _ = receive_send_ready(input_with_nonce_and_timestamp, aes_key, stream).await;

    // Get "ACK" from the receiver
    let mut buf = [0; 3];
    let _ = stream.read_exact(&mut buf).await;
    let _ack = std::str::from_utf8(&buf).unwrap();
    
}
