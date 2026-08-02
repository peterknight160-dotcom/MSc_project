use soft_aes::aes::{aes_dec_ecb, aes_enc_ecb};

use rand::Rng;
use std::env;


use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;
fn test_ntru( message: &[u8], nkeys: u32, nloops: u32) -> Option<bool> {
    println!("Message length: {:?}", message.len());

    let mut dec_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    let mut enc_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    let padding = Some("PKCS7");
    
    // Messege length  can be greater than R3_BYTES, so we need to build an array of R3_BYTES and copy the message into it, padding with zeros if necessary
    // Bytes is a vector of R3_BYTES long, initialized to zero
 
        
        
    
    // Get hostname
    let hostname = hostname::get().unwrap().into_string().unwrap();
  
    println!("Hostname: {}", hostname);
   
    // Outer loop - number of keys to use
    for i in 0..nkeys {
    println!("Key number: {} of {}", i, nkeys);
    // key is a random 32 byte array
    let mut key: [u8; 32] = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

       
        for _ in 0..nloops {
       
            let start_encrypt = Instant::now();
            let ciphertext = aes_enc_ecb(&message, &key, padding).expect("Encryption failed");
            let encrypt_time = start_encrypt.elapsed().as_micros();
            
            *enc_time_hash.entry(encrypt_time).or_insert(0) += 1;
            let start_decrypt = Instant::now();
            let _plaintext = aes_dec_ecb(&ciphertext, &key, padding).expect("Decryption failed");
            let decrypt_time = start_decrypt.elapsed().as_micros();
            *dec_time_hash.entry(decrypt_time).or_insert(0) += 1;
           
        }
    }
    let stats_enc = stats_from_btree(&enc_time_hash, "AES256 Encryption");
    let stats_dec = stats_from_btree(&dec_time_hash, "AES256 Decryption");
    // Get mean + 2 std devs
    let twosigma_enc = stats_enc.mean + 2.0 * stats_enc.std_dev;
    let twosigma_dec = stats_dec.mean + 2.0 * stats_dec.std_dev;

    let _ = draw_histogram_from_btree(&enc_time_hash, "AES256_Encryption", twosigma_enc);
    let _ = draw_histogram_from_btree(&dec_time_hash, "AES256_Decryption", twosigma_dec);
    println!("Stats Encryption for {} :{} ",hostname, stats_enc);
    println!("Stats Decryption for {} :{} ",hostname, stats_dec);



    Some(true)
}


fn main() {
    // Get iterations from the env vars
    let ekeys = env::var("KEYS").ok(); //Get result and convert option
    let nkeys: u32;

    match ekeys.is_some() {
        true => nkeys = ekeys.unwrap().parse::<u32>().unwrap(),
        false => nkeys = 10,
    }
    let eloops = env::var("LOOPS").ok(); //Get result and convert option
    let nloops: u32;

    match eloops.is_some() {
        true => nloops = eloops.unwrap().parse::<u32>().unwrap(),
        false => nloops = 10,
    }
    // Read message from file json.txt
    let message = std::fs::read("json.txt").expect("Unable to read file");

    let start = Instant::now();

    test_ntru( &message, nkeys, nloops);

    let total_time = start.elapsed().as_millis();
    let hours : u128 = total_time / 3600_000;
    let minutes : u128 = (total_time % 3600_000) / 60_000;
    let seconds : u128 = (total_time % 60_000) / 1000;
    let milliseconds : u128 = total_time % 1000;
    if hours == 0 && minutes == 0 {
        println!("Total time: {}.{:03} seconds", seconds, milliseconds);
    } else if hours == 0 {
        println!("Total time: {} minutes, {}.{:03} seconds", minutes, seconds, milliseconds);
    } else {
        println!("Total time: {} hours, {} minutes, {}.{:03} seconds", hours, minutes, seconds, milliseconds);
    }
    
   
}

/* 
let plaintext = b"Example plaintext."; 
let key = b"Very secret key."; 
let padding = Some("PKCS7");

let encrypted = aes_enc_ecb(plaintext, key, padding).expect("Encryption failed");
let decrypted = aes_dec_ecb(&encrypted, key, padding).expect("Decryption failed");


*/