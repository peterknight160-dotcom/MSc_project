use std::io::{self, Error, ErrorKind};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
//use tokio_postgres::{NoTls, Error as PgError};
use postcard;

use rand::*;
use std::sync::Arc;




//include!("keys.rs");



use ed25519_dalek::{ SigningKey,VerifyingKey,Signer,Verifier}; // Used for signing and verifying messages
use x25519_dalek::{EphemeralSecret, PublicKey};  // Used for key exchange
use serde::{Deserialize, Serialize};
//use serde_json::Result;

use soft_aes::aes::{aes_dec_ecb, aes_enc_ecb};

use ntrulp::key::priv_key::*;
use ntrulp::key::pub_key::*;
use ntrulp::key::kem_error::KemErrors;
use ntrulp::params::params::*;
use ntrulp::ntru::cipher::static_bytes_encrypt;
use ntrulp::ntru::std_cipher; 

use ntrulp::poly::r3::R3;
use ntrulp::poly::rq::Rq;
use ntrulp::rng::{self, random_small, short_random};


#[derive(Serialize, Deserialize, Debug)]
struct AuthenticationPackage {
    privatekey: Option<SigningKey>,
    publickey: VerifyingKey,
    payload: PayloadType,
    client_id: String, // client_id not used by the receiver
}
/* #[derive(Serialize, Deserialize, Debug)]
struct PubKeyPackage {
    publickey: VerifyingKey,
    client_id: String, // Not used by the client.
} */
#[derive(Serialize, Deserialize, Debug)]
struct SignedCipherText {
    ciphertext: Vec<u8>,
    signature: ed25519_dalek::Signature,
    payload: PayloadType,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignedRQ {
    text: Vec<u8>,
    signature: ed25519_dalek::Signature,
}

//type KyberPubKey = Vec<u8>;

#[derive(Serialize, Deserialize, Debug)]
struct SignedPubKey {
    pub_key: PublicKey,
    signature: ed25519_dalek::Signature,
}
#[derive(Serialize, Deserialize, Debug)]
enum PayloadType {
    SenderKey,
    VerifierKey,
}

#[derive(Serialize, Deserialize, Debug)]
struct OBDmessage {
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
#[allow(unused)]
pub struct SignatureKeys {
      pub public_key: VerifyingKey,
    pub signing_key: Option<SigningKey>,
    pub verifier_key: VerifyingKey,
    pub my_id: String,
}
#[warn(unused)]
#[derive(Debug, Clone, Deserialize)]
pub struct Measurement {
    pub unit: String,
    pub value: f64,
}

//Need to make fields can be optional, as not all fields will be present in the JSON data.
#[derive(Debug, Clone, Deserialize)]
pub struct VehicleTelemetry {
    pub air_intake_temp: Option<Measurement>,
    pub altitude: Option<Measurement>,
    pub ambient_air_temp: Option<Measurement>,
    pub barometric_pressure: Option<Measurement>,

    pub dtc_number: Option<String>,

    pub engine_coolant_temp: Option<Measurement>,
    pub engine_load_value: Option<f64>,
    pub engine_rpm: Option<Measurement>,
    pub engine_runtime: Option<String>,

    pub epoch: Option<u64>,
    pub equiv_ratio_value: Option<f64>,
    pub fuel_level_value: Option<f64>,

    pub intake_manifold_pressure: Option<Measurement>,

    pub latitude: Option<f64>,
    pub longitude: Option<f64>,

    pub maf: Option<Measurement>,

    #[serde(rename = "short term fuel trim bank 1")]
    pub short_term_fuel_trim_bank_1: Option<f64>,

    pub speed: Option<Measurement>,

    pub throttle_pos_value: Option<f64>,
    pub timing_advance_value: Option<f64>,

    pub vehicle_id: Option<String>,
}
#[derive(Debug, Clone)]
pub struct VehicleTelemetryData {
    pub speed: Option<Measurement>,
    pub vehicle_id: Option<String>,
    pub epoch: Option<u64>,
}
//Client and Receiver - steps 1 and 2
pub async fn get_keys_from_control(addr: &str) -> Result<SignatureKeys, std::io::Error> {
    // Bind to address and port (e.g., 127.0.0.1:8080)
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {} ...", addr);


    let mut my_public_key: VerifyingKey = VerifyingKey::from_bytes(&[0u8; 32]).unwrap();
    let mut my_verifying_key: VerifyingKey = VerifyingKey::from_bytes(&[0u8; 32]).unwrap();
    let mut my_signing_key: Option<SigningKey> = None;
    let mut have_signing_key: bool = false;
    let mut have_verifier_key: bool = false;
    let mut my_id: String = String::new();

    println!("Waiting for control to send keys ...");
    // Accept incoming connections
    loop {
        let (mut stream, _) = listener.accept().await?;
        println!("Accepted connection from control ...");

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;

        let len = u32::from_be_bytes(len_buf);

        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;

        let deserialized: AuthenticationPackage = postcard::from_bytes(&buf).unwrap();
        println!("Received signed AuthenticationPackage from control ...");

        println!("Received keys from control ...");
        // Decrypt the ciphertext

        match deserialized.payload {
            PayloadType::SenderKey => {
            
                my_public_key = deserialized.publickey;
                my_id = deserialized.client_id;

                my_signing_key = deserialized.privatekey;
                have_signing_key = true;
            }
            PayloadType::VerifierKey => {
                my_verifying_key = deserialized.publickey;
                have_verifier_key = true;
            }
        }

        if have_signing_key && have_verifier_key {
            break;
        }
        //
    }

    Ok(SignatureKeys {
        public_key: my_public_key,
        signing_key: my_signing_key,
        verifier_key: my_verifying_key,
        my_id,
    })
}

//Client  Step3
pub async fn send_signed_rq(
    signature_keys: &SignatureKeys,
    stream: &mut TcpStream,
) -> Result<String, io::Error> {
    let text = "Ready to send".as_bytes();

    // use ED25519 signature to sign the text and send it to the receiver

    let signing_key = signature_keys.signing_key.as_ref().unwrap();

    let signature = signing_key.sign(text);

    let signed_message = SignedRQ {
        text: text.to_vec(),
        signature,
    };
    let sender_bytes = postcard::to_allocvec(&signed_message).unwrap();

    stream.write_u32(sender_bytes.len() as u32).await?;
    stream.write_all(&sender_bytes).await?;
    Ok(String::from("Ok"))
}

// Receiver Step3
pub async fn receive_signed_rq(
    signature_keys: &SignatureKeys,
    received: &[u8],
) -> Result<String, io::Error> {
    let signed_message: SignedRQ = postcard::from_bytes(received)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let signature = signed_message.signature;

    // Check keypair signature and return the text if valid, else return an error
  

     let verifier_key = &signature_keys.verifier_key;
     if verifier_key.verify(&signed_message.text, &signature).is_ok() {
        Ok(String::from_utf8(signed_message.text).unwrap())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Authorisation failed in receive_signed_rq",
        ))

    }
}
//Receiver  Step 4

/*
use x25519_dalek::{EphemeralSecret, PublicKey};

let alice_secret = EphemeralSecret::random();
let alice_public = PublicKey::from(&alice_secret);


ⓘ

let bob_secret = EphemeralSecret::random();
let bob_public = PublicKey::from(&bob_secret);



let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);



let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
*/


// Key generated in receiver, this module signs and serializes it, and returns to receiver
pub fn ec25519_key_to_send(
    signature_keys: &SignatureKeys,
    receiver_public: &PublicKey,
) -> Result<Vec<u8>, io::Error> {


    //let my_text = "Have some ML_KEM_keys".as_bytes();

     let signing_key = signature_keys.signing_key.as_ref().unwrap();

    let signature = signing_key.sign(receiver_public.as_bytes());

    let signed_message = SignedPubKey {
        pub_key: receiver_public.clone(),
        signature,
    };
    let signed_message = postcard::to_allocvec(&signed_message).unwrap();

    Ok(signed_message)
}

//Client Step 4
pub async fn get_ec25519_keys(
    signature_keys: &SignatureKeys,
    stream: &mut TcpStream,
) -> Result<PublicKey, io::Error> {
    let len = stream.read_u32().await?;

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    let signed_message: SignedPubKey = postcard::from_bytes(&buf).unwrap();
    let signature = signed_message.signature;

    
     let verifier_key = signature_keys.verifier_key;
     if verifier_key.verify(signed_message.pub_key.as_bytes(), &signature).is_ok() {
        Ok(signed_message.pub_key)
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Authorisation failed in receive_signed_rq",
        ))

    }
}

//Client Step 5
// As receiver Step 4

//Receiver Step 5
// As client Step 4


//Receiver Step 7

pub fn receive_message(aes_key: &[u8], received: &[u8]) -> Result<String, io::Error> {
    let deserialized: OBDmessage = postcard::from_bytes(received).unwrap();

    // Decrypt the ciphertext and handle any resulting errors using match
    match aes_dec_ecb(deserialized.ciphertext.as_slice(), &aes_key, Some("PKCS7")) {
        Ok(byte_stream) => match String::from_utf8(byte_stream) {
            Ok(v) => return Ok(v),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("UTF-8 conversion error: {}", e),
                ));
            }
        },
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Decryption failed: {}", e),
            ));
        }
    }
}

//Client Step 7
pub async fn receive_send_ready(
    text: String,
    aes_key: &[u8],
    stream: &mut TcpStream,
) -> Result<u16, io::Error> {
    let encrypted = OBDmessage {
        ciphertext: aes_enc_ecb(&text.as_bytes(), aes_key, Some("PKCS7")).unwrap(),
    };

    let serialized = postcard::to_allocvec(&encrypted).unwrap();
    stream.write_u32(serialized.len() as u32).await?;
    stream.write_all(&serialized).await?;

    /*
    let encrypted = aes_enc_ecb(&verifier_payload_json.as_bytes(), &my_aes256, padding)
       .expect("Encryption failed"); */
    Ok(1)
}

pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 32];
    rand::rng().fill(&mut nonce[..]);
    nonce
}

// Database routines

pub async fn log_message_to_database(
    client: Arc<tokio_postgres::Client>,
    data: &VehicleTelemetryData,
) -> Result<(), io::Error> {
    let vehicle = data
        .vehicle_id
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());
    let speed = data.speed.as_ref().map_or(0.0, |s| s.value);
    let speed_unit = data
        .speed
        .as_ref()
        .map_or("Unknown".to_string(), |s| s.unit.clone());
    let epoch = data.epoch.unwrap_or(0) as i64;

    client
        .execute(
            "INSERT INTO captures (vehicle, epoch, speed, speed_unit) VALUES ($1, $2, $3, $4)",
            &[&vehicle, &epoch, &speed, &speed_unit],
        )
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("Database error: {:?}", e)))?;

    Ok(())
}

pub async fn log_authentication_to_database(
    client: Arc<tokio_postgres::Client>,
    dongle: &str,
    message: &str,
) -> Result<(), io::Error> {
    println!(
        "Logging authentication to database: dongle: {}, message: {}",
        dongle, message
    );

    match client
        .execute(
            "INSERT INTO logging.authentication (client, result) VALUES ($1, $2)",
            &[&dongle, &message],
        )
        .await
    {
        Ok(_) => (),
        Err(e) => println!("Database error: {:?}", e),
    }

    Ok(())
}


use chacha20::{ChaCha20   };
use chacha20::cipher::{KeyIvInit, StreamCipher};


pub fn receive_message2(aes_key: &[u8], received: &[u8]) -> Result<String, io::Error> {
    let deserialized: OBDmessage = postcard::from_bytes(received).unwrap();
    let nonce: [u8; 12] = [0x24; 12];



    let mut cipher = ChaCha20::new_from_slices(aes_key, &nonce).expect("Failed to create cipher");
        // Decrypt the ciphertext and handle any resulting errors using match
    let mut decrypted = deserialized.ciphertext.clone();
    cipher.apply_keystream(&mut decrypted);
    match String::from_utf8(decrypted) {
        Ok(s) => Ok(s),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to convert decrypted bytes to string: {}", e),
        )),
    }
}





//Client Step 7  - Chacha20 encryption
pub async fn receive_send_ready2(
    text: String,
    aes_key: &[u8],
    stream: &mut TcpStream,
) -> Result<u16, io::Error> {
    let nonce: [u8; 12] = [0x24; 12];
    let mut cipher = ChaCha20::new_from_slices(aes_key, &nonce).expect("Failed to create cipher");

    let encrypted = OBDmessage {
        ciphertext: {
            let mut buf = text.as_bytes().to_vec();
            cipher.apply_keystream(&mut buf);
            buf
        },
    };

    let serialized = postcard::to_allocvec(&encrypted).unwrap();
    stream.write_u32(serialized.len() as u32).await?;
    stream.write_all(&serialized).await?;

    /*
    let encrypted = aes_enc_ecb(&verifier_payload_json.as_bytes(), &my_aes256, padding)
       .expect("Encryption failed"); */
    Ok(1)
}

//Client Step 7  - NTRU encryption
pub async fn receive_send_ready3(
    text: String,
    pk: ntrulp::key::pub_key::PubKey,
    stream: &mut TcpStream,
) -> Result<u16, io::Error> {
    //let nonce: [u8; 12] = [0x24; 12];
    let mut rng = rand::rng() ;
    let encrypted = std_cipher::bytes_encrypt(&mut rng, text.as_bytes(), pk.clone()).unwrap(); 
    let encrypted = OBDmessage {
        ciphertext: encrypted,
    };

    let serialized = postcard::to_allocvec(&encrypted).unwrap();
    stream.write_u32(serialized.len() as u32).await?;
    stream.write_all(&serialized).await?;

    /*
    let encrypted = aes_enc_ecb(&verifier_payload_json.as_bytes(), &my_aes256, padding)
       .expect("Encryption failed"); */
    Ok(1)
}


pub fn receive_message3(sk: ntrulp::key::priv_key::PrivKey, received: &[u8]) -> Result<String, io::Error> {
    let deserialized: OBDmessage = postcard::from_bytes(received).unwrap();
    //let nonce: [u8; 12] = [0x24; 12];



    let decrypted = std_cipher::bytes_decrypt(&deserialized.ciphertext, sk.clone() ).unwrap();
    match String::from_utf8(decrypted) {
        Ok(s) => Ok(s),
        Err(e) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to convert decrypted bytes to string: {}", e),
        )),
    }
}