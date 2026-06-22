use ml_dsa::{MlDsa87, Generate, Keypair, SigningKey, Signer, Verifier};
use std::time::Instant;

fn check_fips204(message: &[u8], iterations: usize) {
    println!("Message length: {:?}", message.len());

    // Generate key pair and signature
let sk = SigningKey::<MlDsa87>::generate();
let vk = sk.verifying_key();



    //Generate both public and secret keys

    let start_keygen = Instant::now();
  
    for _ in 0..iterations {
        let sk = SigningKey::<MlDsa87>::generate();
    let _vk = sk.verifying_key();

    }
   
    let step0 = start_keygen.elapsed();
    println!("Key generation took {:.2?} in total", step0);
    println!(
        "Key generation took {:.2?} per iteration",
        step0 / iterations as u32
    );
   
    let start_sign = Instant::now();
    // let mut dump = Vec::new();
  
    for _ in 0..iterations {
    let _ = sk.sign(message);
    }
    let step2 = start_sign.elapsed();
    println!("Generating signature took {:.2?} in total", step2);
    println!(
        "Generating signature took {:.2?} per signature",
        step2 / iterations as u32
    );
   
    let sig = sk.sign(message);
    
    let start_verify = Instant::now();
    
    for _ in 0..iterations {
        let _ = vk.verify(message, &sig);
    }
    let step3 = start_verify.elapsed();
    println!("Verifying signature took {:.2?} in total", step3);
    println!(
        "Verifying signature took {:.2?} per signature",
        step3 / iterations  as u32
    );
   
  
    let _v = vk.verify(message, &sig); // Use the public to verify message signature
  
    }

fn main() {
    // Read message from file json.txt
    let message = std::fs::read("json.txt").expect("Unable to read file");
    // Read number of iterations from console input
    println!("Enter number of iterations:");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    let iterations: usize = input.trim().parse().expect("Please enter a number");

     check_fips204(&message, iterations);
    
}
