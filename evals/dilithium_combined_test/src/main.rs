use dilithium::{ML_DSA_44, ML_DSA_65, ML_DSA_87, MlDsaKeyPair};
use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;
fn check_fips204(message: &[u8], nkeys: u32, nloops: u32) -> Option<bool> {
    println!("Message length: {:?}", message.len());

    let mut key_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    let mut sign_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    // Generate key pair and signature

    // Outer loop - number of keys to use
    for _ in 0..nkeys {
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
    let stats44 = stats_from_btree(&key_time_hash, "ML_DSA_44 Keys Generation");
    // Get mean + 2 std devs
    let twosigma = stats44.mean + 2.0 * stats44.std_dev;

    let _ = draw_histogram_from_btree(&key_time_hash, "ML_DSA_44KeysGeneration", twosigma);
    println!(        "Stats {} ",stats44           );

    let stats44 =  stats_from_btree(&sign_time_hash, "ML_DSA_44 Message Signing");
    let twosigma = stats44.mean + 2.0 * stats44.std_dev;
    let _ = draw_histogram_from_btree(&sign_time_hash, "ML_DSA_44MessageSigning", twosigma);
    println!(
        "Stats {} ", stats44
        
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
    let stats65=  stats_from_btree(&key_time_hash, "ML_DSA_65 Keys Generation");
    let twosigma = stats65.mean + 2.0 * stats65.std_dev;


   let _ = draw_histogram_from_btree(&key_time_hash, "ML_DSA_65KeysGeneration", twosigma);
   
    println!(
        "Stats {} ",stats65
       );

    let stats65 =  stats_from_btree(&sign_time_hash, "ML_DSA_65 Message Signing")   ;
   let twosigma = stats65.mean + 2.0 * stats65.std_dev;


        let _ = draw_histogram_from_btree(&sign_time_hash, "ML_DSA_65MessageSigning", twosigma);
    println!(
        "Stats {} ",stats65
       
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
    let stats87 = stats_from_btree(&key_time_hash, "ML_DSA_87 Keys Generation");
    // Get mean + 2 std devs
    let twosigma = stats87.mean + 2.0 * stats44.std_dev;

    let _ = draw_histogram_from_btree(&key_time_hash, "ML_DSA_87KeysGeneration", twosigma);
    println!(        "Stats {} ",stats87           );

    let stats87 =  stats_from_btree(&sign_time_hash, "ML_DSA_87 Message Signing");
    let twosigma = stats87.mean + 2.0 * stats44.std_dev;
    let _ = draw_histogram_from_btree(&sign_time_hash, "ML_DSA_87MessageSigning", twosigma);
    println!(
        "Stats {} ", stats87
        
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
