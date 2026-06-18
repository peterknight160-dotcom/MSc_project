use dilithium::{ML_DSA_44, ML_DSA_65, ML_DSA_87,MlDsaKeyPair};
use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;
fn check_fips204(message: &[u8], nkeys: u32, nloops: u32) -> Option<bool> {
    println!("Message length: {:?}", message.len());

    let mut key_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    let mut sign_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    // Generate key pair and signature

    // Outer loop - number of keys to use
    for _ikeys in 0..nkeys {
        let start_key = Instant::now();
        let kp = MlDsaKeyPair::generate(ML_DSA_44).unwrap();
        let key_time = start_key.elapsed().as_micros();

        *key_time_hash.entry(key_time).or_insert(0) += 1;

        for _ in 0..nloops {
            let start_sign = Instant::now();
            let _ = kp.sign(&message, &[]).unwrap();
            let sign_time = start_sign.elapsed().as_micros();
            *sign_time_hash.entry(sign_time).or_insert(0) += 1;
        }
    }
    let _= draw_histogram_from_btree(& key_time_hash, "ML_DSA_44 Keys Generation");
    println!(
        "Stats {} ",
        stats_from_btree(key_time_hash, "ML_DSA_44 Keys Generation")
    );
let _= draw_histogram_from_btree(& sign_time_hash, "ML_DSA_44 Message Signing");
    println!(
        "Stats {} ",
        stats_from_btree(sign_time_hash, "ML_DSA_44 Message Signing")
    );

 let mut key_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    let mut sign_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    // Generate key pair and signature

    // Outer loop - number of keys to use
    for _ikeys in 0..nkeys {
        let start_key = Instant::now();
        let kp = MlDsaKeyPair::generate(ML_DSA_65).unwrap();
        let key_time = start_key.elapsed().as_micros();

        *key_time_hash.entry(key_time).or_insert(0) += 1;

        for _ in 0..nloops {
            let start_sign = Instant::now();
            let _ = kp.sign(&message, &[]).unwrap();
            let sign_time = start_sign.elapsed().as_micros();
            *sign_time_hash.entry(sign_time).or_insert(0) += 1;
        }
    }

    println!(
        "Stats {} ",
        stats_from_btree(key_time_hash, "ML_DSA_65 Keys Generation")
    );
    println!(
        "Stats {} ",
        stats_from_btree(sign_time_hash, "ML_DSA_65 Message Signing")
    );
 let mut key_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    let mut sign_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    // Generate key pair and signature

    // Outer loop - number of keys to use
    for _ikeys in 0..nkeys {
        let start_key = Instant::now();
        let kp = MlDsaKeyPair::generate(ML_DSA_87).unwrap();
        let key_time = start_key.elapsed().as_micros();

        *key_time_hash.entry(key_time).or_insert(0) += 1;

        for _ in 0..nloops {
            let start_sign = Instant::now();
            let _ = kp.sign(&message, &[]).unwrap();
            let sign_time = start_sign.elapsed().as_micros();
            *sign_time_hash.entry(sign_time).or_insert(0) += 1;
        }
    }

    println!(
        "Stats {} ",
        stats_from_btree(key_time_hash, "ML_DSA_87 Keys Generation")
    );
    println!(
        "Stats {} ",
        stats_from_btree(sign_time_hash, "ML_DSA_87 Message Signing")
    );




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

    if check_fips204(&message, nkeys, nloops).unwrap() {
        println!("Validation is good");
    }
}
