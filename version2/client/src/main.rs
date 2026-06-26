use core_utils::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";

fn main() -> std::io::Result<()> {
    // Step 1
    let _signature_keys = get_keys_from_control(ADDR);
    // Now do stuff with them

    println!("Have both keys, ready to rock and roll");

    // Sleep for 100ms
    //Step 3
    std::thread::sleep(std::time::Duration::from_millis(100));

    let s = send_signed_rq(RECEIVER_ADDR);

    if s.is_ok() {
        println!("Got {}", s.unwrap());
    }

    //Step 4
    println!("Waiting for ml_keys");
    let s = get_ml_keys(ADDR);

    if s.is_ok() {
        println!("Got \"{}\"", s.unwrap());
    }

    std::thread::sleep(std::time::Duration::from_millis(100));
    //Step 5

    println!("about to send_ciphertext ");
    let s = send_ciphertext(RECEIVER_ADDR);
    if s.is_ok() {
        println!("Got {}", s.unwrap());
    }

    //Step 5
    let s = receive_send_ready(ADDR);
    if s.is_ok() {
        println!("Got {}", s.unwrap());
    }

    Ok(())
}
