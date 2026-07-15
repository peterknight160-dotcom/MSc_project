use ntrulp::key::priv_key::*;
use ntrulp::key::pub_key::*;
use ntrulp::key::kem_error::KemErrors;
use ntrulp::params::params::*;
use ntrulp::ntru::cipher::static_bytes_encrypt;
use ntrulp::poly::r3::R3;
use ntrulp::poly::rq::Rq;
use ntrulp::rng::{random_small, short_random};


use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats::*;
fn test_ntru(pub_key: Rq, _priv_key: PrivKey, message: &[u8], nkeys: u32, nloops: u32) -> Option<bool> {
    println!("Message length: {:?}", message.len());

    //let mut dec_time_hash: BTreeMap<u128, u32> = BTreeMap::new();
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
       
        for _ in 0..nloops {
            let start_encrypt = Instant::now();
            for bytes in &bytes_matrix {
                let _encrypted = static_bytes_encrypt(&bytes, &pub_key);
            }
            
            let encrypt_time = start_encrypt.elapsed().as_micros();
           
            *enc_time_hash.entry(encrypt_time).or_insert(0) += 1;
           
        }
    }
    let stats_enc = stats_from_btree(&enc_time_hash, "NTRU Encryption");
    // Get mean + 2 std devs
    let twosigma = stats_enc.mean + 3.0 * stats_enc.std_dev;

    let _ = draw_histogram_from_btree(&enc_time_hash, "NTRU_Encryption", twosigma);
    println!(        "Stats {} ",stats_enc           );



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

    let (sk, pk) = generate_keypair().unwrap();

    test_ntru(pk, sk, &message, nkeys, nloops);
   
}

