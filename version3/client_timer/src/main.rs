//use base65::*;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
struct Ping {
    sequence_number: u64,
}

use postcard::{self, to_allocvec};




use std::io::{self};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;


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
    
    
    // Sleep for a second to allow the receiver to start up
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Now to do the performance test

    let eloops = std::env::var("LOOPS").ok(); //Get result and convert option
    let nloops: u64;

    match eloops.is_some() {
        true => nloops = eloops.unwrap().parse::<u64>().unwrap(),
        false => nloops = 10,
    }

    
    let ewait = std::env::var("WAIT").ok(); //Get result and convert option
    let nwait: u64;

    match ewait.is_some() {
        true => nwait = ewait.unwrap().parse::<u64>().unwrap(),
        false => nwait = 3,
    }

    let mut ping_time_hash: BTreeMap<u128, u32> = BTreeMap::new();

      for i  in 0..nloops+10 {
        let start = Instant::now();
        let mut stream = TcpStream::connect(receiver_addr).await?;

        let packet = Ping  {
           sequence_number: i,
        };
        let sender_bytes = postcard::to_allocvec(&packet).unwrap();
        // Send packet to receiver
        stream.write_u32(sender_bytes.len() as u32).await?;
        stream.write_all(&sender_bytes).await?;

        // A
         let len = stream.read_u32().await?;
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;
        
        
        let _received_packet: Ping = postcard::from_bytes(&buf).unwrap();
        let latency = start.elapsed().as_micros();
        *ping_time_hash.entry(latency).or_insert(0) += 1;  

        

        // Disconnect from the receiver
        let _ = stream.shutdown().await;

        // Wait for 3 milliseconds before the next iteration
        if nwait > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(nwait)).await;
        }
        
    }

        let stats_ping = stats_from_btree(&ping_time_hash, "Stats Ping");
    // Get mean + 2 std devs
    let twosigma = stats_ping.mean + 2.0 * stats_ping.std_dev;

    let _ = draw_histogram_from_btree(&ping_time_hash, "Stats_Ping", twosigma);
    println!(        "Stats {} ",stats_ping           );
  
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
