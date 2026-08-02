use chacha20::{ChaCha20   };
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

use rand::Rng;
use std::env;


use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;
fn test_ntru( message: &[u8], nkeys: u32, nloops: u32) -> Option<bool> {
    println!("Message length: {:?}", message.len());

    let mut dec_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    let mut enc_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    
    
    
        
    
    // Get hostname
    let hostname = hostname::get().unwrap().into_string().unwrap();
  
    println!("Hostname: {}", hostname);
   
    // Outer loop - number of keys to use
    for i in 0..nkeys {
    println!("Key number: {} of {}", i, nkeys);
    // key is a random 32 byte array
    let mut key: [u8; 32] = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
    let nonce: [u8; 12] = [0x24; 12];
    let mut cipher = ChaCha20::new_from_slices(&key, &nonce).expect("Failed to create cipher");

       
        for _ in 0..nloops {
       
            let start_encrypt = Instant::now();
            let mut ciphertext = message.to_vec();
            
            cipher.apply_keystream(&mut ciphertext);
            
            
            let encrypt_time = start_encrypt.elapsed().as_micros();
            
            *enc_time_hash.entry(encrypt_time).or_insert(0) += 1;
            cipher.seek(0);
            let start_decrypt = Instant::now();
            let mut decrypted = ciphertext.clone();
            cipher.apply_keystream(&mut decrypted);
            let decrypt_time = start_decrypt.elapsed().as_micros();

            
            *dec_time_hash.entry(decrypt_time).or_insert(0) += 1;
           
        }
    }
    let stats_enc = stats_from_btree(&enc_time_hash, "ChaCha20 Encryption");
    let stats_dec = stats_from_btree(&dec_time_hash, "ChaCha20 Decryption");
    // Get mean + 2 std devs
    let twosigma_enc = stats_enc.mean + 2.0 * stats_enc.std_dev;
    let twosigma_dec = stats_dec.mean + 2.0 * stats_dec.std_dev;

    let _ = draw_histogram_from_btree(&enc_time_hash, "ChaCha20_Encryption", twosigma_enc);
    let _ = draw_histogram_from_btree(&dec_time_hash, "ChaCha20_Decryption", twosigma_dec);
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
use chacha20::{ChaCha20   };
use chacha20::cipher::{KeyIvInit, StreamCipher};

 
    let nonce: [u8; 12] = [0x24; 12];
    // Create a new ChaCha20 cipher instance with the provided key and nonce

    let mut cipher = ChaCha20::new_from_slices(aes_key, &nonce).expect("Failed to create cipher");
        // Decrypt the ciphertext and handle any resulting errors using match
        // Decrypted is initally the ciphertext, but will be modified in place to contain the decrypted data
    
    cipher.apply_keystream(&mut decrypted);
    
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
*/