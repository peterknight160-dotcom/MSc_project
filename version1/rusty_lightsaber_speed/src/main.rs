/*

use rusty_saber::api::{
  CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};
use rusty_saber::kem::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
use rusty_saber::rng::AesState;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
  let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
  let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
  let mut ct = [0u8; CRYPTO_CIPHERTEXTBYTES];
  let mut ss_a = [0u8; CRYPTO_BYTES];
  let mut ss_b = [0u8; CRYPTO_BYTES];
  let mut rng = AesState::new();
  //rng.randombytes_init([0u8; 48]);  // TODO use a proper seed (like bytes from /dev/urandom) here

  // Party a: generate public key `pk` and secret key `sk`
  crypto_kem_keypair(&mut pk, &mut sk, &mut rng)?;
  // Party b: generate a shared secret `ss_a` and ciphertext `ct` from the public key `pk`
  crypto_kem_enc(&mut ct, &mut ss_a, &mut pk, &mut rng)?;
  // Party a: derive the same shared secret `ss_b` from the ciphertext `ct` and the secret key `sk`
  crypto_kem_dec(&mut ss_b, &mut ct, &mut sk)?;

  assert_eq!(ss_a, ss_b);
  Ok(())
}
*/

use rusty_saber::api::{
  CRYPTO_BYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};
use rusty_saber::kem::{crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair};
use rusty_saber::rng::AesState;
use std::error::Error;

use std::collections::BTreeMap;
use std::time::Instant;
use useful_stats_plain::*;
fn check_fips203(nloops: u32) -> Option<u32>{
    // 512

    let mut key_time_hash: BTreeMap<u128, u32> = BTreeMap::new();

   
    //  loop - number of keys to use
    for _ in 0..nloops {
        let start_key = Instant::now();
      let mut pk = [0u8; CRYPTO_PUBLICKEYBYTES];
  let mut sk = [0u8; CRYPTO_SECRETKEYBYTES];
  let mut ct = [0u8; CRYPTO_CIPHERTEXTBYTES];
  let mut ss_a = [0u8; CRYPTO_BYTES];
  let mut ss_b = [0u8; CRYPTO_BYTES];
  let mut rng = AesState::new();
  //rng.randombytes_init([0u8; 48]);  // TODO use a proper seed (like bytes from /dev/urandom) here

  // Party a: generate public key `pk` and secret key `sk`
  crypto_kem_keypair(&mut pk, &mut sk, &mut rng).ok()?;
  // Party b: generate a shared secret `ss_a` and ciphertext `ct` from the public key `pk`
  crypto_kem_enc(&mut ct, &mut ss_a, &mut pk, &mut rng).ok()?;
  // Party a: derive the same shared secret `ss_b` from the ciphertext `ct` and the secret key `sk`
  crypto_kem_dec(&mut ss_b, &mut ct, &mut sk).ok()?;

        let key_time = start_key.elapsed().as_micros();
        *key_time_hash.entry(key_time).or_insert(0) += 1;
    }

    let stats512 = stats_from_btree(&key_time_hash, "LightSaber Keys Swap");
   
    println!("Stats {} ", stats512);
   Some(1)
    
}

fn main() -> Result<(), Box<dyn Error>> {
    // Get iterations from the env vars

    let eloops = env::var("LOOPS").ok(); //Get result and convert option
    let nloops: u32;

    match eloops.is_some() {
        true => nloops = eloops.unwrap().parse::<u32>().unwrap(),
        false => nloops = 10,
    }

    check_fips203(nloops);
      Ok(())
}
