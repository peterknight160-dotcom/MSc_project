use chacha20::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const HOWMANY: u32 = 1000000;

fn main() {
    let time1 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .to_string();
    let bytes = time1.as_bytes();
    let mut seed = [0u8; 32];
    for (i, value) in bytes.iter().enumerate() {
        seed[i] = *value;
    }
    for (i, value) in bytes.iter().enumerate() {
        seed[31 - i] = *value;
    }
    println!("Seed is {:?}", seed);

    //println!("return_val: {:?} ", return_val);
    // let time2 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    //  println!{"time2 is {} ", time2}
    let mut rng = ChaCha20Rng::from_seed(seed);
    let start = Instant::now();

    for _ in 0..HOWMANY/128 {
        let mut sum = 0u64;
        for _ in 0..128 {
            sum += rng.next_u64() <<2;
           
        }
         println!(" Random number is {}", sum);
    }

    let elapsed = start.elapsed();

    println!("That took {:.2?}", elapsed);
    println!("That took {:.2?} per random", elapsed / HOWMANY);
}

//    return_val= SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
