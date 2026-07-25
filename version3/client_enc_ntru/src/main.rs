use base65::*;
use core_utils_classic::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";
const JSON_FILE: &str = "JSON.csv";
use client_enc_ntru::{CsvReader, json_doc_from_reader};

use std::io::{self, BufRead};
use std::fs::File;
use std::path::Path;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use useful_stats::*;
use std::collections::BTreeMap;
use std::time::Instant;

use ntrulp::key::priv_key::*;
use ntrulp::key::pub_key::*;
use ntrulp::key::kem_error::KemErrors;
use ntrulp::params::params::*;
use ntrulp::ntru::cipher::static_bytes_encrypt;
use ntrulp::poly::r3::R3;
use ntrulp::poly::rq::Rq;
use ntrulp::rng::{random_small, short_random};


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


     // Generate a keypair for the NTRU encryption scheme
     let mut rng = rand::rng();
    let mut g: R3;
    let f: Rq = Rq::from(short_random(&mut rng).unwrap());
    let sk = loop {
        g = R3::from(random_small(&mut rng));

        match PrivKey::compute(&f, &g) {
            Ok(s) => break s,
            Err(_) => continue,
        };
    };
    let pk = PubKey::compute(&f, &g).unwrap();

    // Send the private key to the receiver (in a real application, you would not do this)
    let sk_bytes = sk.to_bytes();
    //let pk_bytes = pk.to_bytes();
   
    println!("SK_bytes: {:?}", sk_bytes);
    println!("SK_bytes length: {}", sk_bytes.len());

    



      // Connect to the receiver
    let mut stream = TcpStream::connect(receiver_addr).await?;

    //Write the lengthf of SK to the stream 
    stream.write_all(&(sk_bytes.len() as u32).to_be_bytes()).await?;
    //Write the SK to the stream
    stream.write_all(&sk_bytes).await?;
     
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
            //println!("JSON Document: {}", json_doc);
            jsons.push(json_doc);
        }
    }

    let eloops = env::var("LOOPS").ok(); //Get result and convert option
    let nloops: u32;

    match eloops.is_some() {
        true => nloops = eloops.unwrap().parse::<u32>().unwrap(),
        false => nloops = 10,
    }

    let ebytes = env::var("BYTES").ok(); //Get result and convert option
    let nbytes: u32;

    match ebytes.is_some() {
        true => nbytes = ebytes.unwrap().parse::<u32>().unwrap(),
        false => nbytes = 1024,
    }

    // Use nbytes to determine how many bytes to send in each message
    println!("Sending {} messages of {} bytes each", nloops, nbytes);
    let one_json = jsons[0].len();
    println!("One JSON document is {} bytes", one_json);
    let njsons = (nbytes + one_json as u32 - 1) / one_json as u32;

    println!("Sending {} JSON documents in each message", njsons);

    let mut enc_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    
    
    let mut nonce: u64 = 0;
    let mut i: usize = 0;
    let shared_secret = pk.to_bytes();
    let shared_secret = &shared_secret;
    for _ in 0..nloops {    

       

       
        nonce += 1;
        
        
        let mut json_doc_to_send = String::from(&jsons[i]);
        for _ in 1..njsons {
          i = (i+1) % jsons.len();
         json_doc_to_send.push_str(&jsons[i]);
      
        }   
         let start_encrypt = Instant::now();
        send(&json_doc_to_send, shared_secret, &nonce, &mut stream).await;
        // }
      
        let elapsed_encrypt = start_encrypt.elapsed().as_micros();
        *enc_time_hash.entry(elapsed_encrypt).or_insert(0) += 1;
    }
    send("END", shared_secret, &nonce, &mut stream).await;

     let stats_enc = stats_from_btree(&enc_time_hash, "ChaCha20 Encryption");
    // Get mean + 2 std devs
    let twosigma = stats_enc.mean + 2.0 * stats_enc.std_dev;

    let _ = draw_histogram_from_btree(&enc_time_hash, "ChaCha20_Encryption", twosigma);
    println!(        "Stats {} ",stats_enc           );

    
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
} */


async fn send(input: &str, aes_key: &[u8], nonce: &u64, stream: &mut TcpStream) {
    // Add nonce and timestamp to the input
    // Format nonce as 20-digit zero-padded string

    let nonce_str = base64_from_str(&format!("{:020}", nonce)).unwrap();
    let timestmp = get_time_as_millis_base64();
    let input_with_nonce_and_timestamp = nonce_str + &timestmp + &input;
    //println!("Sending input: {}", input_with_nonce_and_timestamp);
    let _ = receive_send_ready2(input_with_nonce_and_timestamp, aes_key, stream).await;
}
