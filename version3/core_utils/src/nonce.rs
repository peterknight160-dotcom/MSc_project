use rand::rngs::{StdRng,SysRng};
use rand::{SeedableRng, TryRng};
use std::time::SystemTime;

use base65::{base64_from_bytes, base64_to_bytes};

//use chrono::{DateTime, Utc};
pub fn generate_nonce_base64() -> String{
    let mut nonce = vec![0u8; 32];
    
   let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();

    //let mut rng = ChaCha20Rng::from_entropy();
    rng.try_fill_bytes(&mut nonce).unwrap();
    base64_from_bytes(&nonce).unwrap()

}

//Write a function that returns the current time in milliseconds since the epoch and returns [u8]
pub fn get_time_as_millis_base64() ->String{
    let now = SystemTime::now();
    let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    //since_epoch.as_millis().to_be_bytes().iter().filter(|x| **x >0).cloned().collect::<Vec<u8>>()
    let time = since_epoch.as_millis().to_be_bytes().to_vec()[8..].to_vec();
   

   base64_from_bytes(&time).unwrap()
   
}

pub fn return_time_as_millis_from_base64(base64_time: &str) -> u128 {
    let time_bytes = base64_to_bytes(base64_time).unwrap();
    let mut full_bytes = [0u8; 16];
    full_bytes[8..].copy_from_slice(&time_bytes);
    u128::from_be_bytes(full_bytes)
}

pub fn get_time_as_millis_base64_bad() ->String{
    let now = SystemTime::now();
    let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    //since_epoch.as_millis().to_be_bytes().iter().filter(|x| **x >0).cloned().collect::<Vec<u8>>()
    let time = (since_epoch.as_millis()  - 20000).to_be_bytes().to_vec()[8..].to_vec();
   

   base64_from_bytes(&time).unwrap()
   
}


