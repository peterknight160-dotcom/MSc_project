use std::io::{self, Error, ErrorKind};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
//use tokio_postgres::{NoTls, Error as PgError};
use postcard;

use rand::*;
use std::sync::Arc;




//include!("keys.rs");




use serde::{Deserialize, Serialize};
//use serde_json::Result;


type SigningKey = Vec<u8>; // Placeholder for the signing key, replace with actual signing key type

type VerifyingKey = Vec<u8>; // Placeholder for the verifying key, replace with actual verifying key type


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
    signature: Vec<u8>,  
    payload: PayloadType,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignedRQ {
    text: Vec<u8>,
    signature: Vec<u8>, 
}

//type KyberPubKey = Vec<u8>;

#[derive(Serialize, Deserialize, Debug)]
struct SignedPubKey {
    pub_key: Vec<u8>,    
    signature: Vec<u8> ,
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

// Don't probably need this, as this is the no encryption version, and the keys are sent in the clear .
pub async fn get_keys_from_control(addr: &str) -> Result<SignatureKeys, std::io::Error> {


    Ok(SignatureKeys {
        public_key: vec![0u8; 32], // Placeholder for the public key, replace with actual public key bytes
        signing_key: Some(vec![0u8; 64]), // Placeholder for the signing key, replace with actual signing key bytes
        verifier_key: vec![0u8; 32], // Placeholder for the verifier key, replace with actual verifier key bytes
        my_id: "AY50EAU".to_string(),
    })
}

//Client  Step3
pub async fn send_signed_rq(
    _signature_keys: &SignatureKeys,
    stream: &mut TcpStream,
) -> Result<String, io::Error> {
    let text = "Ready to send".as_bytes();

   

    let signature = vec![0u8; 64]; // Placeholder for the signature, replace with actual signing logic

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
    _signature_keys: &SignatureKeys,
    received: &[u8],
) -> Result<String, io::Error> {
    let signed_message: SignedRQ = postcard::from_bytes(received)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let signature = signed_message.signature;

    // Check keypair signature and return the text if valid, else return an error
  

    Ok(String::from_utf8(signed_message.text).unwrap())
    
}
//Receiver  Step 4

    
// Key generated in receiver, this module signs and serializes it, and returns to receiver
pub fn text_key_to_send(
    _signature_keys: &SignatureKeys,
    receiver_public: &Vec<u8>,
) -> Result<Vec<u8>, io::Error> {


    //let my_text = "Have some ML_KEM_keys".as_bytes();

     let signing_key = vec![0u8; 64]; // Placeholder for the signing key, replace with actual signing key bytes

    let signature = vec![0u8; 64]; // Placeholder for the signature, replace with actual signing logic

    let signed_message = SignedPubKey {
        pub_key: vec![0u8; 32], // Placeholder for the public key, replace with actual public key bytes
        signature,
    };
    let signed_message = postcard::to_allocvec(&signed_message).unwrap();

    Ok(signed_message)
}

//Client Step 4
pub async fn get_text_keys(
    _signature_keys: &SignatureKeys,
    stream: &mut TcpStream,
) -> Result<Vec<u8>, io::Error> {
    let len = stream.read_u32().await?;

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    let signed_message: SignedPubKey = postcard::from_bytes(&buf).unwrap();
    let signature = signed_message.signature;

    
    Ok(signed_message.pub_key)
    
}

//Client Step 5
// As receiver Step 4

//Receiver Step 5
// As client Step 4


//Receiver Step 7


//Client Step 7


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



