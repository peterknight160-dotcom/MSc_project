

use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signature;
use std::time::Instant;
use std::collections::BTreeMap;
use useful_stats::*;

fn check_ed25519 (message: &[u8], nkeys: u32, nloops: u32) {

 println!("Message length: {:?}", message.len());
 let mut dump = Vec::new() ;


  let mut sign_time_hash: BTreeMap<u128, u32> = BTreeMap::new();


let mut csprng = OsRng;
for _ in 0..nkeys {
let signing_key: SigningKey = SigningKey::generate(&mut csprng);

for _ in 0..nloops {
   let start = Instant::now();
let signature: Signature = signing_key.sign(message);

dump.push(signature.to_bytes()[2]);  
 *sign_time_hash.entry(start.elapsed().as_micros() ).or_insert(0) += 1;


}

    



}
let stats255 = stats_from_btree(&sign_time_hash, "ED25519 Keys Generation");
    // Get mean + 2 std devs
    let twosigma = stats255.mean + 2.0 * stats255.std_dev;

    let _ = draw_histogram_from_btree(&sign_time_hash, "ED25519KeysGeneration", twosigma);
    println!(        "Stats {} ",stats255           );
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
    

  
    check_ed25519 (& message, nkeys, nloops)  


}


