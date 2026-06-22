#[allow(unused_imports)]
use fips204::ml_dsa_44; // Could also be ml_dsa_44 or ml_dsa_44.
//use fips204::traits::{SerDes, Signer, Verifier};
use fips204::traits::Signer;
use std::time::Instant;

fn check_fips204(message: &[u8], nkeys: u32, nloops: u32) -> Option<bool> {
    #![allow(unused_variables)]
    println!("Message length: {:?}", message.len());

    // Generate key pair and signature

    let Some((pk1, sk)) = ml_dsa_44::try_keygen().ok() else {
        panic!("At line 7")
    }; // Generate both public and secret keys

    let mut key_time: u128 = 0;

    // Outer loop - number of keys to use
    for _ in 0..nkeys {
        let start_key = Instant::now();
        let Some((pk1, sk)) = ml_dsa_44::try_keygen().ok() else {
            panic!("At line 7");
        };
        key_time += start_key.elapsed().as_micros();
    } // Generate both public and secret keys for this loop
    for _ in 0..nloops {
        let sig: Option<[u8; 2420]> = sk.try_sign(&message, &[]).ok(); // Use the secret key to generate a message signature
        //dump.push(sig.unwrap()[0]);
    }

    println!(" Key creation time {:?}", (key_time as f64)/(nkeys as f64) );

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

    println!("nkeys is: {}, nlookps is: {}  ", nkeys, nloops);

    // Read message from file json.txt
    let message = std::fs::read("json.txt").expect("Unable to read file");

    if check_fips204(&message, nkeys, nloops).unwrap() {
        println!("Validation is good");
    }
}
