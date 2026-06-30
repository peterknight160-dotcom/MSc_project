// Implement the receiver

use std::ptr::read;

use core_utils::*;
use kyber::{MlKemKeyPair, ML_KEM_512,MlKemCiphertext };
//use serde::{Deserialize, Serialize};

const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";

fn main() -> std::io::Result<()> {
    // Step 2
    let signature_keys = match  get_keys_from_control(RECEIVER_ADDR){
         Ok (v) => v,
        Err(_) => panic!("Failed to get keys from controller, exiting"),
    };
     // Step 2 in the flow
    // Now do stuff with them

    println!("Have both keys, ready to rock and roll");

    // Step 3
    let s = receive_signed_rq(&signature_keys,RECEIVER_ADDR);

    if s.is_ok() {
        println!("Got a messge \"{}\" long from receive_signed_rq ", s.unwrap());
    }

    std::thread::sleep(std::time::Duration::from_millis(100));

    let s = send_ml_keys(&signature_keys, ADDR);
  
    let key_pair= s.unwrap();

    //let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_512, key_pair.public_key()).unwrap(); 
    //Step 5
    let s = get_ciphertext(RECEIVER_ADDR);
 
     
    let ct= s.unwrap();

    let ss_receiver = key_pair.decaps(&ct).unwrap(); 

    println!( "Shared Secret is {:?}", ss_receiver.as_bytes() );



       //Step 7
    std::thread::sleep(std::time::Duration::from_millis(100));

    let s = receive_loop(ss_receiver.as_bytes(), RECEIVER_ADDR);
    
    if s.is_ok() {
        println!("Got {} from send_ready ", s.unwrap());
    }

    Ok(())
}
