use std::time::{ SystemTime, UNIX_EPOCH};
use chacha20::ChaCha20Rng;
use rand_core::{SeedableRng, Rng};

fn main() {
    
    let time1 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros().to_string();
    let bytes = time1.as_bytes();
    let mut seed :[u8;32]   = [0;32];
    for (i, value) in bytes.iter().enumerate() {
        seed[i] = *value;
    }
      for (i, value) in bytes.iter().enumerate() {
        seed[31-i] = *value;
    }
    println!( "Seed is {:?}", seed);

    //println!("return_val: {:?} ", return_val);
// let time2 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
//  println!{"time2 is {} ", time2}
let mut rng = ChaCha20Rng::from_seed(seed);
for _ in 0..100 {

println!(" Random number is {}", rng.next_u64() as f32 / u64::MAX as f32);
}
}


//    return_val= SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();