/*

use ml_kem::{
    MlKem768,
    kem::{Decapsulate, Encapsulate, Kem}
};

// Generate a decapsulation/encapsulation keypair
let (dk, ek) = MlKem768::generate_keypair();

// Encapsulate a shared key to the holder of the decapsulation key, receive the shared
// secret `k_send` and the encapsulated form `ct`.
let (ct, k_send) = ek.encapsulate();

// Decapsulate the shared key
let k_recv = dk.decapsulate(&ct);

*/


use ml_kem::{
    MlKem768,
    kem::{Decapsulate, Encapsulate, Kem}
};

use rand::prelude::*;



use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;
fn check_fips203( nloops: u32)  {
    let seed = [ 42u8;32]; 
       let mut rng = rand::rng();
    let mut key_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
   

    //  loop - number of keys to use
        for _ in 0..nloops {
        let start_key = Instant::now();
        let (dk, ek) = MlKem768::generate_keypair_from_rng(&mut rng);
        let (ct, k_send) = ek.encapsulate_with_rng(&mut rng);  
        let k_recv = dk.decapsulate(&ct);
  
        let key_time = start_key.elapsed().as_micros();
        *key_time_hash.entry(key_time).or_insert(0) += 1;
  
        }
    
    let stats768 = stats_from_btree(&key_time_hash, "ML_KEM_768 Keys Swap");
    // Get mean + 2 std devs
    let twosigma = stats768.mean + 2.0 * stats768.std_dev;

    let _ = draw_histogram_from_btree(&key_time_hash, "ML_DSA_768KeysSwap", twosigma);
    println!(        "Stats {} ",stats768           );



    


    
}

fn main() {
    // Get iterations from the env vars
   
    let eloops = env::var("LOOPS").ok(); //Get result and convert option
    let nloops: u32;

    match eloops.is_some() {
        true => nloops = eloops.unwrap().parse::<u32>().unwrap(),
        false => nloops = 10,
    }
    

    check_fips203(nloops);
}
