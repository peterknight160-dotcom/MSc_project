use ntrulp::key::priv_key::*;
use ntrulp::key::pub_key::*;
use ntrulp::key::kem_error::KemErrors;
use ntrulp::params::params::*;
use ntrulp::ntru::std_cipher::{bytes_encrypt, bytes_decrypt};
use ntrulp::poly::r3::R3;
use ntrulp::poly::rq::Rq;
use ntrulp::rng::{random_small, short_random};
//use rand::Rng;
use std::env;


use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;
fn test_ntru( message: &[u8], nkeys: u32, nloops: u32) -> Option<bool> {
    println!("Message length: {:?}", message.len());

    let mut dec_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    let mut enc_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
    
    // Messege length  can be greater than R3_BYTES, so we need to build an array of R3_BYTES and copy the message into it, padding with zeros if necessary
    // Bytes is a vector of R3_BYTES long, initialized to zero
        
    let x = if message.len() % R3_BYTES != 0 {
        message.len() / R3_BYTES + 1
    } else {
        message.len() / R3_BYTES
    };
    // Bytes is a matrix of x rows and R3_BYTES columns, initialized to zero
    let mut bytes_matrix: Vec<[u8; R3_BYTES]> = vec![[0u8; R3_BYTES]; x];
    // Copy message into bytes_matrix
    for i in 0..x {
        let start = i * R3_BYTES;
        let end = if start + R3_BYTES > message.len() {
            message.len()
        } else {
            start + R3_BYTES
        };
        bytes_matrix[i][..end - start].copy_from_slice(&message[start..end]);
    }   

        
        
    

   
    // Outer loop - number of keys to use
    for _ in 0..nkeys {

    let (sk, pk) = generate_keypair().unwrap();
       
        for _ in 0..nloops {
            let mut rng = rand::rng();
            let start_encrypt = Instant::now();
           let ciphertext = bytes_encrypt(&mut rng, message, pk.clone()).unwrap();
            let encrypt_time = start_encrypt.elapsed().as_micros();
            
            *enc_time_hash.entry(encrypt_time).or_insert(0) += 1;
            let start_decrypt = Instant::now();
            let _plaintext = bytes_decrypt(&ciphertext, sk.clone()).unwrap();
            let decrypt_time = start_decrypt.elapsed().as_micros();
            *dec_time_hash.entry(decrypt_time).or_insert(0) += 1;
           
        }
    }
    let stats_enc = stats_from_btree(&enc_time_hash, "NTRU Encryption");
    let stats_dec = stats_from_btree(&dec_time_hash, "NTRU Decryption");
    // Get mean + 2 std devs
    let twosigma_enc = stats_enc.mean + 2.0 * stats_enc.std_dev;
    let twosigma_dec = stats_dec.mean + 2.0 * stats_dec.std_dev;

    let _ = draw_histogram_from_btree(&enc_time_hash, "NTRU_Encryption", twosigma_enc);
    let _ = draw_histogram_from_btree(&dec_time_hash, "NTRU_Decryption", twosigma_dec);
    println!("Stats Encryption {} ", stats_enc);
    println!("Stats Decryption {} ", stats_dec);



    Some(true)
}

pub fn generate_keypair() ->Result<(PrivKey, PubKey), KemErrors> {
   
    let mut rng = rand::rng();
    let mut g: R3;
    let f: Rq = Rq::from(short_random(&mut rng).unwrap());
    let sk = loop {
        g = R3::from(random_small(&mut rng));

        match PrivKey::compute(&f, &g) {
            Ok(s) => break s,
            Err(_) => continue,
        };
    };
    let pk = PubKey::compute(&f, &g).unwrap();

    Ok((sk, pk))
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

    

    test_ntru( &message, nkeys, nloops);
   
}

/* 

let mut origin_plaintext = vec![0u8; 1024];
rng.fill(&mut origin_plaintext);

let ciphertext =
    std_cipher::bytes_encrypt(&mut rng, &origin_plaintext, pk.clone()).unwrap();


assert_eq!(plaintext, origin_plaintext);

*/