// Control Plane for Classic stuff.
// Ed25519 for authentication, Curve25519 for Key Exchange.

use getrandom::{SysRng, rand_core::UnwrapErr};

use ed25519_dalek::{ SigningKey,VerifyingKey};


use serde::{Deserialize, Serialize};

use std::io::{self, Write};
use std::net::TcpStream;

//include!("consts.rs"); // Not clean rust code, but otherwise gets very messy




#[derive(Serialize, Deserialize, Debug)]
struct AuthenticationPackage {
    privatekey: Option<SigningKey>,
    publickey: VerifyingKey,
    payload: PayloadType,
    client_id: String, // client_id not used by the receiver
}
#[derive(Serialize, Deserialize, Debug)]
struct PubKeyPackage {
    publickey: VerifyingKey,
    client_id: String, // Not used by the client.
}
#[derive(Serialize, Deserialize, Debug)]
struct SignedCipherText {
    ciphertext: Vec<u8>,
    signature: ed25519_dalek::Signature,
    payload: PayloadType,
}
#[derive(Serialize, Deserialize, Debug)]
enum PayloadType {
    SenderKey,
    VerifierKey,
}

const CLIENT: &str = "127.0.0.1:8080";
//const RECEIVER: &str = "127.0.0.1:8090";
const RECEIVER_CONTROL: &str = "127.0.0.1:8095";
fn main() {
    // Don't need public key here.

    //  Option Menu
    loop {
        let input = get_input("What would you like to do?");
        match input.as_str() {
            "exit" | "e" => break,
            "client" | "c" => gen_keys(CLIENT, RECEIVER_CONTROL),
            "receiver" | "reciever" | "r" => gen_keys(RECEIVER_CONTROL, CLIENT),
            //"control" => gen_keys(RECEIVER_CONTROL, CLIENT),
            _ => continue,
        }
    }
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

fn gen_keys(sender: &str, verifier: &str) {

  
    // Generate keys & pack into Structure
    let mut csprng = UnwrapErr(SysRng);
    let signing_key : SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key : VerifyingKey = signing_key.verifying_key();

    let sender_payload = AuthenticationPackage {
        privatekey: Some(signing_key),
        publickey: verifying_key,
        payload: PayloadType::SenderKey,
        client_id: String::from("AZ40EUA"),
    };

    let sender_payload_bytes = postcard::to_allocvec(&sender_payload).unwrap();


    // Send message to sender

    if let Ok(mut stream) = TcpStream::connect(sender) {
        let len = (sender_payload_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len).unwrap();
        stream.write_all(&sender_payload_bytes).unwrap();
    } else {
        println!("Couldn't connect to sender side, skipped");
    }

    // Package up public key, senderID, encrypt them and send to verifier.
    let verifier_payload = AuthenticationPackage {
        privatekey: None,
        publickey: verifying_key,
        client_id: String::from("AZ40EUA"),
        payload: PayloadType::VerifierKey,
    };

    let verifier_payload_bytes = postcard::to_allocvec(&verifier_payload).unwrap();
   
    // Send message to verifier

    if let Ok(mut stream) = TcpStream::connect(verifier) {
        let len = (verifier_payload_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len).unwrap();
        stream.write_all(&verifier_payload_bytes).unwrap();
    } else {
        println!("Couldn't connect to verifier side, skipped");
    }

    //let encrypted = aes_enc_ecb(&package.as_bytes(), &my_aes256, padding).expect("Encryption failed");
    //let signature: ed25519_dalek::Signature = my_signing_key.sign(&encrypted, &[]).unwrap();
}
