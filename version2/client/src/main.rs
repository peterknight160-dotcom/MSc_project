use std::io::Read;
use std::net::TcpListener;

use dilithium::{DilithiumKeyPair, DilithiumSignature, ML_DSA_44, ML_DSA_87, MlDsaKeyPair};
use serde::{Deserialize, Serialize};
//use serde_json::Result;
use base65::*;
use soft_aes::aes::aes_dec_ecb;

include!("keys.rs");
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
    payload: PayloadType,
}
#[derive(Serialize, Deserialize, Debug)]
enum PayloadType {
    SenderKey,
    VerifierKey,
}

fn main() -> std::io::Result<()> {
    let control_aes = base64_to_bytes(AES256).unwrap();
    // Bind to address and port (e.g., 127.0.0.1:8080)
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("Listening on 127.0.0.1:8080...");
    let mut buffer = [0; 100_000];
    let mut nbytes: usize = 0;
    let mut my_private_key: Vec<u8> = Vec::new();
    let mut my_public_key: Vec<u8> = Vec::new();
    let mut my_verifying_key: Vec<u8> = Vec::new();
    let mut my_signing_key : DilithiumKeyPair ;
    // Accept incoming connections
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                println!("New connection from: {}", stream.peer_addr()?);

                // Read data from the stream
                match stream.read(&mut buffer) {
                    Ok(bytes_read) => {
                        if bytes_read > 0 {
                            nbytes = bytes_read;
                        }
                    }
                    Err(e) => println!("Failed to read from connection: {}", e),
                }
            }
            Err(e) => println!("Connection failed: {}", e),
        }
        // Have the stuff from control, now do something with it:

        let deserialized: SignedCipherText = serde_json::from_slice(&buffer[..nbytes]).unwrap();

        // Is the signature good?
        let signature = deserialized.signature;

        let ok = MlDsaKeyPair::verify(
            &base64_to_bytes(PUBLIC).unwrap(),
            &signature,
            deserialized.ciphertext.as_slice(),
            &[],
            ML_DSA_87,
        );

        if !ok {
            panic!("Failed to get good client signature from control");
        }
        // Decrypt the ciphertext
        let padding = Some("PKCS7");
        let payload_json_bytes =
            aes_dec_ecb(deserialized.ciphertext.as_slice(), &control_aes, padding)
                .expect("Decrypt failed");
        let payload_json = String::from_utf8(payload_json_bytes).expect("Bad payload");
        // Deconstruct the JSON
        match deserialized.payload {
            PayloadType::SenderKey => {
                let client_config: AuthenticationPackage =
                    serde_json::from_str(&payload_json).unwrap();

                my_private_key = client_config.privatekey;
                my_public_key = client_config.publickey;
                let my_id = client_config.client_id;

                println!("my_private_key {:?}", my_private_key);
                println!("my_public_key {:?}", my_public_key);
                 my_signing_key =
                    DilithiumKeyPair::from_keys(&my_private_key, &my_public_key, ML_DSA_44).expect("Not valid keys");
            }
            PayloadType::VerifierKey => {
                let client_config: PubKeyPackage = serde_json::from_str(&payload_json).unwrap();

                my_verifying_key = client_config.publickey;
            }
        }

        println!("my_private_key {:?}", my_private_key);
        println!("my_public_key {:?}", my_public_key);
        println!("my_verifying_key {:?}", my_verifying_key);

        //
    }

    Ok(())
}
