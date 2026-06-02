

use fips204::ml_dsa_44; // Could also be ml_dsa_44 or ml_dsa_44. 
use fips204::traits::{SerDes, Signer, Verifier};
use std::time::Instant;

fn check_fips204 (message: &[u8] ) -> Option <bool> {

   

// Generate key pair and signature
for (_) in 0..1000{ 
let start2 = Instant::now();
let quick = start2.elapsed();
println!(" That was quick {:.2?}", quick);
}
let start = Instant::now();


let Some((pk1, sk)) = ml_dsa_44::try_keygen().ok() else { panic!("At line 7")};  // Generate both public and secret keys
let step1 =start.elapsed();
println!("Generating keys took {:.2?}", step1) ;

let sig = sk.try_sign(&message, &[]).ok();  // Use the secret key to generate a message signature
let step2 =start.elapsed();
println!("Generating keys took {:.2?}", step2) ;
// Serialize then send the public key, message and signature
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), message, sig);



let (pk_recv, msg_recv) = (pk_send, msg_send);
let sig_recv= sig_send.unwrap();

// Deserialize the public key and signature, then verify the message
let pk2 = ml_dsa_44::PublicKey::try_from_bytes(pk_recv).ok();
let v = pk2?.verify(&msg_recv, &sig_recv, &[]); // Use the public to verify message signature
       Some(v)
}


fn main() {
    let message = [0u8, 1, 2, 3, 4, 5, 6, 7, 8 ];
    if check_fips204(& message).unwrap(){
        println!("Validation is good");
    }


}


/* 
// Use the desired target parameter set.
use fips204::ml_dsa_44; // Could also be ml_dsa_44 or ml_dsa_44. 
use fips204::traits::{SerDes, Signer, Verifier};
let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

// Generate key pair and signature
let (pk1, sk) = ml_dsa_44::try_keygen()?;  // Generate both public and secret keys
let sig = sk.try_sign(&message, &[])?;  // Use the secret key to generate a message signature

// Serialize then send the public key, message and signature
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), message, sig);
let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);

// Deserialize the public key and signature, then verify the message
let pk2 = ml_dsa_44::PublicKey::try_from_bytes(pk_recv)?;
let v = pk2.verify(&msg_recv, &sig_recv, &[]); // Use the public to verify message signature
assert!(v);
    
// Note that the last argument to sign() and verify() is the (NIST specified) context
// value which is typically empty for basic signature generation and verification.


*/