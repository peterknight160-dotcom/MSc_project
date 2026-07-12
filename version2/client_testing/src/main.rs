// Dongle client for testing:
// Can send bad keys
// Bad nonce and bad timestamp

use base65::*;
use core_utils_tokio::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";
const JSON_FILE: &str = "JSON.csv";
use client_testing::{CsvReader, json_doc_from_reader};
use dilithium::{DilithiumKeyPair, DilithiumSignature, ML_DSA_44, ML_DSA_87, MlDsaKeyPair};
use kyber::ML_KEM_512;
use std::io::{self};
use tokio::net::TcpStream;

#[derive(Debug, PartialEq)]
enum TestType {
    BadKeys,
    BadNonce,
    BadTimestamp,
    Null,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Step 1
    let mut signature_keys = match get_keys_from_control(ADDR).await {
        Ok(v) => v,
        Err(e) => panic!(" Have not got a valid signature_keys, {}", e),
    };
    // Get from the user the test to run:
    println!("What test would you like to run? ");
    println!("1. Send bad keys");
    println!("2. Send bad nonce");
    println!("3. Send bad timestamp");
    let input = get_input("Enter the number of the test to run: ");

    let input = input.trim();
    let test: TestType;
    match input {
        "1" => test = TestType::BadKeys,
        "2" => test = TestType::BadNonce,
        "3" => test = TestType::BadTimestamp,
        _ => test = TestType::Null,
    }

    // Now do stuff with them

    println!("Have both keys, ready to rock and roll");

    if test == TestType::BadKeys {
        // Replace the signing key with new ones, but keep the vehicle_id the same

        if let Ok(value) = MlDsaKeyPair::generate(ML_DSA_44) {
            // print type of kp:
            let output = format!("{:?}", value);
            // print 200 characters of the value

            println!("New signing key type: {}", &output[..200.min(output.len())]);

            signature_keys.signing_key = Some(value);
        }
    }

    let mut stream = TcpStream::connect(RECEIVER_ADDR).await?;

    //Step 3

    let _s = match send_signed_rq(&signature_keys, &mut stream).await {
        Ok(v) => v,
        Err(_) => panic!("Failed to send keys, exiting"),
    };

    //Step 4

    //let s = get_ml_keys(&signature_keys, &mut stream).await;
    let pub_key = get_ml_keys(&signature_keys, &mut stream).await.unwrap();

    //Step 5

    let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_512, pub_key.as_slice()).unwrap();
    let shared_secret = ss_sender.as_bytes();
    println!("about to send_ciphertext ");
    let s = send_ciphertext(ct, &mut stream).await;
    if s.is_ok() {
        println!("Got {}", s.unwrap());
    }

    println!(
        "Shared Secret is {:?}",
        base65::base64_from_bytes(shared_secret).unwrap()
    );
    //    Step 7 Loop around, sending stuff to the receiver
    // Set up the json file to send to the receiver

    let mut json_reader = CsvReader::set_up(JSON_FILE).unwrap();
    let headers = json_reader.headers().clone();

    let mut nonce: u64 = 0;
    loop {
        let input =
            get_input("What would you like to send a JSON to the receiver? (Type END to finish)")
                .to_uppercase();

        nonce += if test == TestType::BadNonce { 0 } else { 1 };

        let line = json_reader.next().unwrap().unwrap();
        let json_doc_to_send = json_doc_from_reader(line, &headers, &signature_keys.my_id.as_str());

        match input.as_str() {
            "END" => break,
            "YES" | "Y" => send(json_doc_to_send, shared_secret, &nonce, &mut stream, &test).await,
            _ => (),
        };
    }
    send(
        String::from("END"),
        shared_secret,
        &nonce,
        &mut stream,
        &test,
    )
    .await;
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

async fn send(input: String, aes_key: &[u8], nonce: &u64, stream: &mut TcpStream, test: &TestType) {
    // Add nonce and timestamp to the input
    // Format nonce as 20-digit zero-padded string

    let nonce_str = base64_from_str(&format!("{:020}", nonce)).unwrap();

    let timestamp = if *test == TestType::BadTimestamp {
        get_time_as_millis_base64_bad()
    } else {
        get_time_as_millis_base64()
    };

    let input_with_nonce_and_timestamp = nonce_str + &timestamp + &input;
    //println!("Sending input: {}", input_with_nonce_and_timestamp);
    let _ = receive_send_ready(input_with_nonce_and_timestamp, aes_key, stream).await;
}
