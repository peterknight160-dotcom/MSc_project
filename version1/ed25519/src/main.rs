

use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signature;
use std::time::Instant;

fn check_ed25519 (message: &[u8], iterations: usize) {

 println!("Message length: {:?}", message.len());

// Generate key pair and signature



let mut csprng = OsRng;
let signing_key: SigningKey = SigningKey::generate(&mut csprng);

println!( "Generated signing key: {:?}", signing_key.to_bytes());

let start = Instant::now();
let mut dump = Vec::new();  
for _ in 0..iterations {
   
let signature: Signature = signing_key.sign(message);
dump.push(signature.to_bytes()[2]);  
}
let step2 =start.elapsed();
println!("Generating signature took {:.2?} in total", step2) ;
println!("Generating signature took {:.2?} per signature", step2 / iterations as u32) ;


}


fn main() {

    // Read message from file json.txt
    let message = std::fs::read("json.txt").expect("Unable to read file");
    // Read number of iterations from console input
    println!("Enter number of iterations:");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Failed to read line");
    let iterations: usize = input.trim().parse().expect("Please enter a number");   

  
    check_ed25519 (& message, iterations)  


}


