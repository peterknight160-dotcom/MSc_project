use core_utils_tokio::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";
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

    let _s = match send_signed_rq(&signature_keys, &mut stream).await {
        Ok(v) => v,
        Err(_) => panic!("Failed to send keys, exiting"),
    };

    //Step 4

    //let s = get_ml_keys(&signature_keys, &mut stream).await;
    let pub_key = get_ml_keys(&signature_keys, &mut stream).await.unwrap();

    //Step 5

    let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_512, pub_key.as_slice()).unwrap();
    println!("about to send_ciphertext ");
    let s = send_ciphertext(ct, &mut stream).await;
    if s.is_ok() {
        println!("Got {}", s.unwrap());
    }

    println!("Shared Secret is {:?}", ss_sender.as_bytes());
    //    Step 7 Loop around, sending stuff to the receiver
    loop {
        let input = get_input("What would you like to send (\"END\" will stop the interaction) ");
        match input.as_str() {
            "END" => break,
            _ => send(input, ss_sender.as_bytes(), &mut stream).await,
        };
    }
    send(String::from("END"), ss_sender.as_bytes(), &mut stream).await;

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

async fn send(input: String, aes_key: &[u8], stream: &mut TcpStream) {
    println!("Sending input: {}", input);
    let _ = receive_send_ready(input, aes_key, stream).await;
}
