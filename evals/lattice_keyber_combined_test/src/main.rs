/*

use kyber::{MlKemKeyPair, ML_KEM_768};

let kp = MlKemKeyPair::generate(ML_KEM_768).unwrap();
let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_768, kp.public_key()).unwrap();
let ss_receiver = kp.decaps(&ct).unwrap();
assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());

*/

use kyber::{ML_KEM_512, ML_KEM_768, ML_KEM_1024,MlKemKeyPair};

use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;
fn check_fips203(nloops: u32) {
    // 512

    let mut key_time_hash: BTreeMap<u128, u32> = BTreeMap::new();

     // Pre -run

         for _ in 0..nloops/10 {
       
        let kp = MlKemKeyPair::generate(ML_KEM_512).unwrap();
        let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_512, kp.public_key()).unwrap();
        let ss_receiver = kp.decaps(&ct).unwrap();
       

      
    }
    //  loop - number of keys to use
    for _ in 0..nloops {
        let start_key = Instant::now();
        let kp = MlKemKeyPair::generate(ML_KEM_512).unwrap();
        let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_512, kp.public_key()).unwrap();
        let ss_receiver = kp.decaps(&ct).unwrap();
      

        let key_time = start_key.elapsed().as_micros();
        *key_time_hash.entry(key_time).or_insert(0) += 1;
    }

    let stats512 = stats_from_btree(&key_time_hash, "MLat_KEM_512 Keys Swap");
    // Get mean + 2 std devs
    let twosigma = stats512.mean * 1.25;

    let _ = draw_histogram_from_btree(&key_time_hash, "MLat_KEM_512_Keys_Swap", twosigma);
    println!("Stats {} ", stats512);

    // 768

    let mut key_time_hash: BTreeMap<u128, u32> = BTreeMap::new();

    //  loop - number of keys to use
    for _ in 0..nloops {
        let start_key = Instant::now();
        let kp = MlKemKeyPair::generate(ML_KEM_768).unwrap();
        let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_768, kp.public_key()).unwrap();
        let ss_receiver = kp.decaps(&ct).unwrap();
       

        let key_time = start_key.elapsed().as_micros();
        *key_time_hash.entry(key_time).or_insert(0) += 1;
    }

    let stats768 = stats_from_btree(&key_time_hash, "MLat_KEM_768 Keys Swap");
    // Get mean + 2 std devs
    let twosigma = stats768.mean * 1.25;

    let _ = draw_histogram_from_btree(&key_time_hash, "MLat_KEM_768_Keys_Swap", twosigma);
    println!("Stats {} ", stats768);

    //1024
    let mut key_time_hash: BTreeMap<u128, u32> = BTreeMap::new();

    //  loop - number of keys to use
    for _ in 0..nloops {
        let start_key = Instant::now();
        let kp = MlKemKeyPair::generate(ML_KEM_1024).unwrap();
        let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_1024, kp.public_key()).unwrap();
        let ss_receiver = kp.decaps(&ct).unwrap();
        
        let key_time = start_key.elapsed().as_micros();
        *key_time_hash.entry(key_time).or_insert(0) += 1;
    }

    let stats1024 = stats_from_btree(&key_time_hash, "MLat_KEM_1024 Keys Swap");
    // Get mean + 2 std devs
    let twosigma = stats1024.mean * 1.25;

    let _ = draw_histogram_from_btree(&key_time_hash, "MLat_KEM_1024_Keys_Swap", twosigma);
    println!("Stats {} ", stats1024);
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
