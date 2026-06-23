// Control Plane for PQC stuff.
use base65::*;
use dilithium::{DilithiumKeyPair, DilithiumSignature, ML_DSA_44, MlDsaKeyPair};
use serde::{Deserialize, Serialize};


use std::io::{self, Write};
use std::net::TcpStream;
include!("consts.rs"); // Not clean rust code, but otherwise gets very messy

use soft_aes::aes::{ aes_enc_ecb};

#[derive(Serialize, Deserialize, Debug)]
struct AuthenticationPackage {
    privatekey: Vec<u8>,
    publickey: Vec<u8>,
    client_id: String, // client_id not used by the receiver
}
#[derive(Serialize, Deserialize, Debug)]
struct PubKeyPackage {
    publickey: Vec<u8>,
    client_id: String, // Not used by the client.
}
#[derive(Serialize, Deserialize, Debug)]
struct SignedCipherText {
    ciphertext: Vec<u8>,
    signature: DilithiumSignature,
    payload: PayloadType
}
#[derive(Serialize, Deserialize, Debug)]
enum PayloadType {
    SenderKey,
    VerifierKey
}

const CLIENT: &str ="127.0.0.1:8080";
const RECEIVER: &str ="127.0.0.1:8090";


fn main() {
    // Don't need public key here.

    //  Option Menu
    loop {
        let input = get_input("What would you like to do?");
        match input.as_str() {
            "exit" => break,
            "client" => gen_keys(CLIENT,RECEIVER ),
            "receiver" => gen_keys(RECEIVER, CLIENT),
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

fn gen_keys(sender: &str, verifer :& str) {

    let my_aes256 = base64_to_bytes(AES256).unwrap();
    let my_private_signature = base64_to_bytes(PRIVATE).unwrap();
    let my_public_signature = base64_to_bytes(PUBLIC).unwrap();
    let my_signing_key = DilithiumKeyPair::from_keys(
        &my_private_signature,
        &my_public_signature,
        dilithium::DilithiumMode::Dilithium5,
    )
    .expect("Failed");
    // Generate keys & pack into Structure
    let sender_kp = MlDsaKeyPair::generate(ML_DSA_44).unwrap();
    println!( "sender_kp : {:?}", sender_kp);
    let sender_payload = AuthenticationPackage {
        privatekey: sender_kp.private_key().to_vec(),
        publickey: sender_kp.public_key().to_vec(),
        client_id: String::from("one"),
    };

    let sender_payload_json = serde_json::to_string(&sender_payload).unwrap();

    println!(" sender_payload_json {:?} ", sender_payload_json.len());

    let padding = Some("PKCS7");
    let encrypted = aes_enc_ecb(&sender_payload_json.as_bytes(), &my_aes256, padding)
        .expect("Encryption failed");

    // Sign encrypted with my_private_key

    let signature = my_signing_key.sign(&encrypted, &[]).unwrap();

    let sender_message = SignedCipherText {
        ciphertext: encrypted,
        signature: signature,
        payload: PayloadType::SenderKey,
    };
    let sender_json = serde_json::to_string(&sender_message).unwrap();
    // Send message to sender
     //println!("ciphertext is {:?} ", encrypted);
     println!(" sender_json {:?} ", sender_json.len());
       //println!(" sender_payload_json {:?} ", sender_payload_json);
     let mut stream = TcpStream::connect(sender).unwrap();
     stream.write_all(sender_json.as_bytes()).unwrap();
 


    // Package up public key, senderID, encrypt them and send to verifier.
    let verifier_payload = PubKeyPackage {
         publickey: sender_kp.public_key().to_vec(),
         client_id: String::from("one"),
    };
    
    let verifier_payload_json = serde_json::to_string(&verifier_payload).unwrap();
     let encrypted = aes_enc_ecb(&verifier_payload_json.as_bytes(), &my_aes256, padding)
        .expect("Encryption failed");
     let signature = my_signing_key.sign(&encrypted, &[]).unwrap();

    let verifier_message = SignedCipherText {
        ciphertext: encrypted,
        signature: signature,
        payload: PayloadType::VerifierKey
    };
    let verifier_json = serde_json::to_string(&verifier_message).unwrap();
    // Send message to verifier
   let mut stream = TcpStream::connect(verifer).unwrap();
     stream.write_all(verifier_json.as_bytes()).unwrap();


    //let encrypted = aes_enc_ecb(&package.as_bytes(), &my_aes256, padding).expect("Encryption failed");
    //let signature: dilithium::DilithiumSignature = my_signing_key.sign(&encrypted, &[]).unwrap();
}

