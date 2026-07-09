use std::io::{self, Error, ErrorKind};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_postgres::{NoTls, Error as PgError};
use postcard;

use  rand::*; 
 use std::sync::Arc;


#[macro_use]
mod my_macros;
pub mod nonce;
pub use nonce::{generate_nonce_base64, get_time_as_millis_base64, return_time_as_millis_from_base64};

include!("keys.rs");

use dilithium::{DilithiumKeyPair, DilithiumSignature, ML_DSA_44, ML_DSA_87, MlDsaKeyPair};
use kyber::{MlKemCiphertext, MlKemKeyPair, MlKemSharedSecret};
use serde::{Deserialize, Serialize};
//use serde_json::Result;
use base65::*;
use soft_aes::aes::{aes_dec_ecb,aes_enc_ecb};
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
struct SignedRQ {
    text: Vec<u8>,
    signature: DilithiumSignature,
}

type KyberPubKey = Vec<u8>;

#[derive(Serialize, Deserialize, Debug)]
struct SignedKyberPubKey {
    pub_key: KyberPubKey,
    signature: DilithiumSignature,
}
#[derive(Serialize, Deserialize, Debug)]
enum PayloadType {
    SenderKey,
    VerifierKey,
}

#[derive(Serialize, Deserialize, Debug)]
struct OBDmessage{
    ciphertext: Vec<u8>
}

#[derive(Debug,Clone)]
#[allow(unused)]
pub struct SignatureKeys {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    signing_key: Option<DilithiumKeyPair>,
    verifier_key: Vec<u8>,
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
    let control_aes = base64_to_bytes(AES256).unwrap();
    // Bind to address and port (e.g., 127.0.0.1:8080)
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {} ...", addr);
  
    let mut my_private_key: Vec<u8> = Vec::new();
    let mut my_public_key: Vec<u8> = Vec::new();
    let mut my_verifying_key: Vec<u8> = Vec::new();
    let mut my_signing_key: Option<DilithiumKeyPair> = None;
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

        

        let deserialized: SignedCipherText = postcard::from_bytes(&buf).unwrap();
        println!("Received signed ciphertext from control ...");
        // Is the signature good?
        let signature = deserialized.signature;

        if !MlDsaKeyPair::verify(
            &base64_to_bytes(PUBLIC).unwrap(),
            &signature,
            deserialized.ciphertext.as_slice(),
            &[],
            ML_DSA_87,
        ) {
            panic!("Failed to get good client signature from control");
        }

        println!("Received keys from control ...");
        // Decrypt the ciphertext
        let padding = Some("PKCS7");
        let payload_bytes =
            aes_dec_ecb(deserialized.ciphertext.as_slice(), &control_aes, padding)
                .expect("Decrypt failed");
        //let payload_json = String::from_utf8(payload_json_bytes).expect("Bad payload");
        // Deconstruct the JSON
        match deserialized.payload {
            PayloadType::SenderKey => {
                let client_config: AuthenticationPackage =
                    postcard::from_bytes(&payload_bytes).unwrap();

                my_private_key = client_config.privatekey;
                my_public_key = client_config.publickey;
                my_id = client_config.client_id;

                my_signing_key = Some(
                    DilithiumKeyPair::from_keys(&my_private_key, &my_public_key, ML_DSA_44)
                        .expect("Failed to create signing_key"),
                );
                have_signing_key = true;
            }
            PayloadType::VerifierKey => {
                let client_config: PubKeyPackage = postcard::from_bytes(&payload_bytes).unwrap();

                my_verifying_key = client_config.publickey;
                have_verifier_key = true;
            }
        }


        if have_signing_key && have_verifier_key {
            break;
        }
        //
    }

    Ok(SignatureKeys {
        private_key: my_private_key,
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
    let signature = signature_keys
        .signing_key
        .as_ref()
        .unwrap()
        .sign(text, &[])
        .unwrap();
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
pub async fn receive_signed_rq(signature_keys: &SignatureKeys, received: &[u8]) -> Result<String, io::Error> {
    
        let signed_message: SignedRQ = postcard::from_bytes(received).unwrap();
        let signature = signed_message.signature;

        // Check keypair signature and return the text if valid, else return an error


       if MlDsaKeyPair::verify(
            &signature_keys.verifier_key,
            &signature,
            &signed_message.text,
            &[],
            ML_DSA_44,) {
              Ok(String::from_utf8(signed_message.text).unwrap())
        } else {
           Err(Error::other(
                "Authorisation Failed in receive_signed_rq ",
            ))
        }
    }
   

//Receiver  Step 4

pub fn ml_key_to_send(signature_keys: &SignatureKeys,key_pair: &MlKemKeyPair) -> Result<Vec<u8>, io::Error> {
    //let my_text = "Have some ML_KEM_keys".as_bytes();
  

    let pub_key = key_pair.public_key();
    let signature = signature_keys
        .signing_key
        .as_ref()
        .unwrap()
        .sign(pub_key, &[])
        .unwrap();
    let signed_message = SignedKyberPubKey {
        pub_key: pub_key.to_vec(),
        signature,
    };
    let signed_message = postcard::to_allocvec(&signed_message).unwrap();

   
    Ok(signed_message)
}

//Client Step 4
pub async fn get_ml_keys(signature_keys: &SignatureKeys,stream: &mut TcpStream) -> Result<KyberPubKey, io::Error> {
let len = stream.read_u32().await?;



let mut buf = vec![0u8; len as usize];
stream.read_exact(&mut buf).await?;

   
        let signed_message: SignedKyberPubKey =
            postcard::from_bytes(&buf).unwrap();
        let signature = signed_message.signature;

        if MlDsaKeyPair::verify(
            &signature_keys.verifier_key,
            &signature,
            &signed_message.pub_key,
            &[],
            ML_DSA_44,
        ) {
             Ok(signed_message.pub_key)
        } else {
                 Err(Error::other(
                "Authorisation Failed in receive_signed_rq ",
            ))
        }
}

//Client Step 5

pub async fn send_ciphertext(ct: MlKemCiphertext, stream: &mut TcpStream) -> Result<String, io::Error> {
    let message_bytes = postcard::to_allocvec(&ct).unwrap();
    let len = message_bytes.len() as u32;
    stream.write_u32(len).await?;
    stream.write_all(&message_bytes).await?;

    Ok(String::from("Ok"))
}
//Receiver Step 5
pub fn get_ss_from_ct(buffer: &[u8], key_pair: &MlKemKeyPair ) -> Result<MlKemSharedSecret, io::Error> {
  
    let ct: MlKemCiphertext;
  
        ct = postcard::from_bytes(buffer).unwrap();
     let ss_receiver = key_pair.decaps(&ct).unwrap();

    Ok(ss_receiver)
}

//Receiver Step 7

pub fn receive_message (aes_key: &[u8], received: &[u8]) -> Result<String, io::Error> {
 
        let deserialized: OBDmessage =postcard::from_bytes(received).unwrap();
             let byte_stream = aes_dec_ecb(deserialized.ciphertext.as_slice(), &aes_key,  Some("PKCS7"))
                .expect("Decrypt failed");



        let text = match  String::from_utf8 (byte_stream) {
            Ok(v) => v,
            Err (e) => panic!( "Got {} ",e)
        };
    
    Ok(text)

}

//Client Step 7
pub async fn receive_send_ready(text: String , aes_key: &[u8], stream: &mut TcpStream) -> Result<u16, io::Error> {
    
  
    
    let encrypted =  OBDmessage {
        ciphertext: aes_enc_ecb(&text.as_bytes(), aes_key ,  Some("PKCS7")).unwrap(),
    };

    let serialized = postcard::to_allocvec(&encrypted).unwrap();
    stream.write_u32(serialized.len() as u32).await?;
    stream.write_all(&serialized).await?;

    /*
     let encrypted = aes_enc_ecb(&verifier_payload_json.as_bytes(), &my_aes256, padding)
        .expect("Encryption failed"); */
    Ok (1)
}

pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 32];
    rand::rng().fill(&mut nonce[..]);
    nonce
}


// Database routines

pub async fn log_message_to_database(client: Arc<tokio_postgres::Client>, data : &VehicleTelemetryData) -> Result<(), io::Error> {
    let vehicle = data.vehicle_id.clone().unwrap_or_else(|| "Unknown".to_string());
    let speed = data.speed.as_ref().map_or(0.0, |s| s.value);
    let speed_unit = data.speed.as_ref().map_or("Unknown".to_string(), |s| s.unit.clone());
    let epoch = data.epoch.unwrap_or(0) as i64;    

    
//let speed = speed as f64; // Ensure speed is a f64

    client
        .execute(
            "INSERT INTO captures (vehicle, epoch, speed, speed_unit) VALUES ($1, $2, $3, $4)",
            &[ &vehicle, &epoch, &speed, &speed_unit ],
        )
        .await
        .map_err(|e| Error::new(ErrorKind::Other, format!("Database error: {:?}", e)))?;


    Ok(())
}
