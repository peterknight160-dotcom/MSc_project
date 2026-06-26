use std::io::{self, Error, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};

include!("keys.rs");

use dilithium::{DilithiumKeyPair, DilithiumSignature, ML_DSA_44, ML_DSA_87, MlDsaKeyPair};
use serde::{Deserialize, Serialize};
//use serde_json::Result;
use base65::*;
use soft_aes::aes::aes_dec_ecb;
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

/*#[derive(Serialize, Deserialize, Debug)]
 struct MLKEMKEYS {
  ek: ml_kem::EncapsulationKey,
  signature: DilithiumSignature,

} */
#[derive(Serialize, Deserialize, Debug)]
enum PayloadType {
    SenderKey,
    VerifierKey,
}
#[derive(Debug)]
pub struct SignatureKeys {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    signing_key: Option<DilithiumKeyPair>,
    verifier_key: Vec<u8>,
    my_id: String,
}

//Client and Receiver - steps 1 and 2
pub fn get_keys_from_control(addr: &str) -> Result<SignatureKeys, std::io::Error> {
    let control_aes = base64_to_bytes(AES256).unwrap();
    // Bind to address and port (e.g., 127.0.0.1:8080)
    let listener = TcpListener::bind(addr).expect("Failed to connect to network");
    println!("Listening on {} ...", addr);
    let mut buffer = [0; 100_000];
    let mut nbytes: usize;
    let mut my_private_key: Vec<u8> = Vec::new();
    let mut my_public_key: Vec<u8> = Vec::new();
    let mut my_verifying_key: Vec<u8> = Vec::new();
    let mut my_signing_key: Option<DilithiumKeyPair> = None;
    let mut have_signing_key: bool = false;
    let mut have_verifier_key: bool = false;
    let mut my_id: String = String::new();
    // Accept incoming connections
    for stream in listener.incoming() {
        if stream.is_ok() {
            nbytes = stream.unwrap().read(&mut buffer)?;
        } else {
            return Err(Error::new(ErrorKind::Other, "Bad stream"));
        }

        let deserialized: SignedCipherText = serde_json::from_slice(&buffer[..nbytes]).unwrap();

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
                my_id = client_config.client_id;

                my_signing_key = Some(
                    DilithiumKeyPair::from_keys(&my_private_key, &my_public_key, ML_DSA_44)
                        .expect("Failed to create signing_key"),
                );
                have_signing_key = true;
            }
            PayloadType::VerifierKey => {
                let client_config: PubKeyPackage = serde_json::from_str(&payload_json).unwrap();

                my_verifying_key = client_config.publickey;
                have_verifier_key = true;
            }
        }

        println!(
            "my_private_key {} {:?}",
            my_private_key.len(),
            &my_private_key[0..my_private_key.len().min(30)]
        );
        println!(
            "my_public_key {} {:?}",
            my_public_key.len(),
            &my_public_key[0..my_public_key.len().min(30)]
        );
        println!(
            "my_verifying_key {} {:?}",
            my_verifying_key.len(),
            &my_verifying_key[0..my_verifying_key.len().min(30)]
        );

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
pub fn send_signed_rq(receiver_addr: &str) -> Result<String, io::Error> {
    let my_text = "Ready to send".as_bytes();
    let mut stream = TcpStream::connect(receiver_addr)?;
    stream.write_all(my_text)?;
    Ok(String::from("Ok"))
}

// Receiver Step3
pub fn receive_signed_rq(addr: &str) -> Result<String, io::Error> {
    let listener = TcpListener::bind(addr)?;

    let (mut socket, _remote_addr) = listener.accept()?;

    let mut buffer = [0u8; 1000];
    let bytes_read = socket.read(&mut buffer)?;

    if bytes_read > 0 {
        return Ok(String::from_utf8_lossy(&buffer[..bytes_read]).to_string());
    } else {
        return Err(Error::new(ErrorKind::Other, "Nothing read"));
    }
}

//Receiver  Step 4

pub fn send_ml_keys(addr: &str) -> Result<String, io::Error> {
    let my_text = "Have some ML_KEM_keys".as_bytes();
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(my_text)?;
    Ok(String::from("Ok"))
}

//Client Step 4
pub fn get_ml_keys(addr: &str) -> Result<String, io::Error> {
    let listener = TcpListener::bind(addr)?;
    let (mut socket, _remote_addr) = listener.accept()?;
    let mut buffer = [0u8; 1000];
    let bytes_read = socket.read(&mut buffer)?;
    if bytes_read > 0 {
        return Ok(String::from_utf8_lossy(&buffer[..bytes_read]).to_string());
    } else {
        return Err(Error::new(ErrorKind::Other, "Nothing read"));
    }
}

//Client Step 5

pub fn send_ciphertext(receiver_addr: &str) -> Result<String, io::Error> {
    let my_text = "Here is the ciphertext".as_bytes();
    let mut stream = TcpStream::connect(receiver_addr)?;
    stream.write_all(my_text)?;
    Ok(String::from("Ok"))
}
//Receiver Step 5
pub fn get_ciphertext(addr: &str) -> Result<String, io::Error> {
    let listener = TcpListener::bind(addr)?;
    let (mut socket, _remote_addr) = listener.accept()?;
    let mut buffer = [0u8; 1000];
    let bytes_read = socket.read(&mut buffer)?;
    if bytes_read > 0 {
        return Ok(String::from_utf8_lossy(&buffer[..bytes_read]).to_string());
    } else {
        return Err(Error::new(ErrorKind::Other, "Nothing read"));
    }
}

//Receiver Step 7

pub fn send_ready(addr: &str) -> Result<String, io::Error> {
    let my_text = "Ready to send encrypted text".as_bytes();
    let mut stream = TcpStream::connect(addr)?;
    stream.write_all(my_text)?;
    Ok(String::from("Ok"))
}

//Client Step 7
pub fn receive_send_ready(addr: &str) -> Result<String, io::Error> {
    let listener = TcpListener::bind(addr)?;
    let (mut socket, _remote_addr) = listener.accept()?;
    let mut buffer = [0u8; 1000];
    let bytes_read = socket.read(&mut buffer)?;
    if bytes_read > 0 {
        return Ok(String::from_utf8_lossy(&buffer[..bytes_read]).to_string());
    } else {
        return Err(Error::new(ErrorKind::Other, "Nothing read"));
    }
}

/* pub fn generate_ml_kem_keys ( signaturekeys: SignatureKeys , addr: &str) -> MLKEMKEYS {

    // Wait for request from dongle
     // Bind to address and port (e.g., 127.0.0.1:8080)
    let listener = TcpListener::bind(addr).expect("Failed to connect to network");
      let mut buffer = [0; 10_000];

    match listener.accept() {
       Ok((stream, addr)) => println!("new client: {addr:?}"),
       Err(e) => println!("couldn't get client: {e:?}"),
     }

                // Read data from the stream
     match stream.read(&mut buffer) {
        Ok(bytes_read) => {
           if bytes_read > 0 {
                  let received = String::from_utf8_lossy(&buffer[..bytes_read]);
                      }
                  }
              Err(e) => eprintln!("Failed to read from connection: {}", e),
            }
        // Decompose Request and check signature
        let deserialized : SignedRQ = serde_json::from_slice(&buffer[..nbytes]).unwrap();
        // Signature good
        let signature = deserialized.signature;
        if ! MlDsaKeyPair::verify(
              &base64_to_bytes(PUBLIC).unwrap(),
              &signature,
               deserialized.ciphertext.as_slice(),
              &[],
             ML_DSA_44, )  {
               panic!("Failed to get good client signature from control");
        }
        if ! deserialized.text == "Ready to send".as_bytes() {
              panic!("Wrong RQ ");
        }
          MLKEMKEYS {  }



    }


}






pub fn send_signed_rq (signaturekeys: SignatureKeys , receiver_addr: &str )  -> String
{
    let my_text= "Ready to send".as_bytes();
    // Signed text using my
    let signing_key = signaturekeys.signing_key.unwrap();
    let signature = signing_key.sign (my_text, &[] ).unwrap();
    let my_signedrq = SignedRQ {text: Vec::from (my_text),
          signature};
    let request_json= serde_json::to_string(&my_signedrq).unwrap();
    if let Ok(mut stream) = TcpStream::connect(receiver_addr) {
         stream.write_all(request_json.as_bytes()).unwrap();

    } else {
        println!("Couldn't connect to verifer side, skipped");
    }

} */
