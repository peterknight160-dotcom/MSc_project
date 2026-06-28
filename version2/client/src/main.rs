use core_utils::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";
use kyber::{ML_KEM_512, MlKemCiphertext, MlKemKeyPair};

fn main() -> std::io::Result<()> {
    // Step 1
    let signature_keys = match get_keys_from_control(ADDR) {
        Ok(v) => v,
        Err(e) => panic!(" Have not got a valid signature_keys, {}", e),
    };
    // Now do stuff with them

    println!("Have both keys, ready to rock and roll");

    // Sleep for 100ms
    //Step 3
    std::thread::sleep(std::time::Duration::from_millis(100));

    let s = match send_signed_rq(&signature_keys, RECEIVER_ADDR) {
        Ok(v) => v,
        Err(_) => panic!("Failed to send keys, exiting"),
    };

    println!(" Got \"{:?}\" from send_signed_rq", s);

    //Step 4
    println!("Waiting for ml_keys");
    let s = get_ml_keys(&signature_keys, ADDR);

    if s.is_ok() {
        println!("Got \"{:?}\" from get_ml_keys ", s.as_ref().unwrap());
    }
    let pub_key = s.unwrap();

    std::thread::sleep(std::time::Duration::from_millis(100));
    //Step 5

    let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_512, pub_key.as_slice()).unwrap();
    println!("about to send_ciphertext ");
    let s = send_ciphertext(ct, RECEIVER_ADDR);
    if s.is_ok() {
        println!("Got {}", s.unwrap());
    }

    println!("Shared Secret is {:?}", ss_sender.as_bytes());
    //Step 7
    let s = receive_send_ready(ADDR);
    if s.is_ok() {
        println!("Got {}", s.unwrap());
    }

    Ok(())
}
