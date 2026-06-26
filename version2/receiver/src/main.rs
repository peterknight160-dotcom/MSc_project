// Implement the receiver

use core_utils::*;

const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";

fn main() -> std::io::Result<()> {
    // Step 2
    let _signature_keys = get_keys_from_control(RECEIVER_ADDR); // Step 2 in the flow
    // Now do stuff with them

    println!("Have both keys, ready to rock and roll");

    // Step 3
    let s = receive_signed_rq(RECEIVER_ADDR);

    if s.is_ok() {
        println!("Got {} from receive_signed_rq ", s.unwrap());
    }

    std::thread::sleep(std::time::Duration::from_millis(100));

    let s = send_ml_keys(ADDR);
    if s.is_ok() {
        println!("Got {} from send_ml_keys ", s.unwrap());
    }

    //Step 5
    let s = get_ciphertext(RECEIVER_ADDR);
    if s.is_ok() {
        println!("Got {} from send_ml_keys ", s.unwrap());
    }

    //Step 7
    std::thread::sleep(std::time::Duration::from_millis(100));

    let s = send_ready(ADDR);
    if s.is_ok() {
        println!("Got {} from send_ready ", s.unwrap());
    }

    Ok(())
}
