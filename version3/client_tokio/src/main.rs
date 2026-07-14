use base65::*;
use core_utils_tokio::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";
const JSON_FILE: &str = "JSON.csv";
use client_tokio::{CsvReader, json_doc_from_reader};
use kyber::ML_KEM_512;
use std::io::{self};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Step 1
    let signature_keys = match get_keys_from_control(ADDR).await {
        Ok(v) => v,
        Err(e) => panic!(" Have not got a valid signature_keys, {}", e),
    };
    // Now do stuff with them

    println!("Have both keys, ready to rock and roll");

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

    println!("Sent ciphertext to the receiver, so now we both have the shared secret" );

    println!("Shared Secret is {:?}", base65::base64_from_bytes(shared_secret).unwrap());
    //    Step 7 Loop around, sending stuff to the receiver
    // Set up the json file to send to the receiver

    let mut json_reader = CsvReader::set_up(JSON_FILE).unwrap();
    let headers = json_reader.headers().clone();

    let mut nonce: u64 = 0;
    loop {
        let input =
            get_input("What would you like to send a JSON to the receiver? (Type END to finish)")
                .to_uppercase();
        nonce += 1;
        let line = json_reader.next().unwrap().unwrap();
        let json_doc_to_send = json_doc_from_reader(line, &headers, &signature_keys.my_id.as_str());

        match input.as_str() {
            "END" => break,
            "YES" | "Y" => send(json_doc_to_send, shared_secret, &nonce, &mut stream).await,
            _ => (),
        };
    }
    send(String::from("END"), shared_secret, &nonce, &mut stream).await;
    // Wait for 100ms
    std::thread::sleep(std::time::Duration::from_millis(100));

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

async fn send(input: String, aes_key: &[u8], nonce: &u64, stream: &mut TcpStream) {
    // Add nonce and timestamp to the input
    // Format nonce as 20-digit zero-padded string

    let nonce_str = base64_from_str(&format!("{:020}", nonce)).unwrap();
    let timestmp = get_time_as_millis_base64();
    let input_with_nonce_and_timestamp = nonce_str + &timestmp + &input;
    //println!("Sending input: {}", input_with_nonce_and_timestamp);
    let _ = receive_send_ready(input_with_nonce_and_timestamp, aes_key, stream).await;
}
