

use fips204::ml_dsa_87; // Could also be ml_dsa_44 or ml_dsa_44. 
use fips204::traits::{SerDes, Signer, Verifier};
use std::time::Instant;

fn check_fips204 (message: &[u8], iterations: usize) -> Option <bool> {

 println!("Message length: {:?}", message.len());

// Generate key pair and signature




let Some((pk1, sk)) = ml_dsa_87::try_keygen().ok() else { panic!("At line 7")};  // Generate both public and secret keys



let start = Instant::now();
let mut dump = Vec::new();
for _ in 0..iterations {
   
let sig = sk.try_sign(&message, &[]).ok();  // Use the secret key to generate a message signature
dump.push(sig.unwrap()  [0]);  
}
let step2 =start.elapsed();
println!("Generating signature took {:.2?} in total", step2) ;
println!("Generating signature took {:.2?} per signature", step2 / iterations as u32) ;
let sig = sk.try_sign(&message, &[]).ok();
// Serialize then send the public key, message and signature
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), message, sig);



let (pk_recv, msg_recv) = (pk_send, msg_send);
let sig_recv= sig_send.unwrap();

// Deserialize the public key and signature, then verify the message
let pk2 = ml_dsa_87 ::PublicKey::try_from_bytes(pk_recv).ok();
let v = pk2?.verify(&msg_recv, &sig_recv, &[]); // Use the public to verify message signature
       Some(v)
}


fn main() {

    // Read message from file json.txt
    let message = std::fs::read("json.txt").expect("Unable to read file");
    // Read number of iterations from console input
    println!("Enter number of iterations:");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Failed to read line");
    let iterations: usize = input.trim().parse().expect("Please enter a number");   

  
    if check_fips204(& message, iterations).unwrap(){
        println!("Validation is good");
    }


}


