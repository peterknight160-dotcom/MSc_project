// Control Plane for PQC stuff.
use base65::*;
use dilithium::{DilithiumKeyPair, ML_DSA_44, ML_DSA_87, MlDsaKeyPair};
use std::io;
include!("consts.rs"); // Not clean rust code, but otherwise gets very messy

use soft_aes::aes::{aes_enc_ecb, aes_dec_ecb};

fn main() {
  
   
    // Don't need public key here.
  
  //  Option Menu
    loop {
        let input = get_input("What would you like to do?");
        match input.as_str() {
            "exit" => break,
            "client" => gen_keys_for_client(),
            "receiver" => gen_keys_for_receiver(),
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

fn gen_keys_for_client() {

    let my_aes256 = base64_to_bytes(AES256).unwrap();
    let my_private_signature = base64_to_bytes(PRIVATE).unwrap();
    let my_public_signature = base64_to_bytes(PUBLIC).unwrap();
    let my_signing_key=
     DilithiumKeyPair::from_keys(&my_private_signature , &my_public_signature, dilithium::DilithiumMode::Dilithium3).expect("Failed");
    // Generate keys
    let kp = MlDsaKeyPair::generate(ML_DSA_44).unwrap();
    let private_key = base64_from_bytes(kp.private_key()).unwrap();
    let public_key = base64_from_bytes(kp.public_key()).unwrap();

    // Package up private key, client ID,  encrypt them and send it to client.
    let client_id = "one";
   
       
   let  package = private_key + "\n" + &public_key + "\n" + client_id ;   
   
    
   let padding = Some("PKCS7");
    
    let encrypted = aes_enc_ecb(&package.as_bytes(), &my_aes256, padding).expect("Encryption failed");

    // Sign encrypted with my_private 

           
     let signature = my_signing_key.sign(&encrypted, &[]).unwrap();
       


    // Package up public key, client ID, encrypt them and send to receiver.
     let  package = public_key + "\n" + client_id ;
     let encrypted = aes_enc_ecb(&package.as_bytes(), &my_aes256, padding).expect("Encryption failed");
         let signature = my_signing_key.sign(&encrypted, &[]).unwrap();



     


}
fn gen_keys_for_receiver() {
    // Generate keys
    // Package up private key, encrypt it and send it to receiver.

    // Package up public key,  encrypt it and send to client.
}

/*

struct myMLDSAKeyPair {
    pub private_key: String ,
    pub public_key: String
}

 fn gen_ml_dsa_key_pair() -> Option <myMLDSAKeyPair> {

   let kp = MlDsaKeyPair::generate(ML_DSA_87).unwrap();
   let private_key = base64_from_bytes( kp.private_key())?;
   let public_key = base64_from_bytes (kp.public_key())?;

  Some (myMLDSAKeyPair {
    private_key,
    public_key
  })

}*/
