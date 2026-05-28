

use fips204::ml_dsa_87; // Could also be ml_dsa_87 or ml_dsa_87. 
use fips204::traits::{SerDes, Signer, Verifier};

fn check_fips204 (message: &[u8] ) -> Option <bool> {

   

// Generate key pair and signature
 println! ("Got to line 11");

let Some((pk1, sk)) = ml_dsa_87::try_keygen().ok() else { panic!("At line 7")};  // Generate both public and secret keys

println! ("Got to line 15");
let sig = Box::new(sk.try_sign(&message, &[]).ok());  // Use the secret key to generate a message signature
  println!( "Sig is {:?}", sig);
// Serialize then send the public key, message and signature
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), message, sig);
let pk_send = Box::new(pk_send);
let msg_send = Box::new(msg_send );
let sig_send=Box::new(sig_send);
let (pk_recv, msg_recv) = (pk_send, msg_send);
let sig_recv= Box::new(sig_send.unwrap());

// Deserialize the public key and signature, then verify the message
let pk2 = ml_dsa_87::PublicKey::try_from_bytes(*pk_recv).ok();
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
use fips204::ml_dsa_87; // Could also be ml_dsa_87 or ml_dsa_87. 
use fips204::traits::{SerDes, Signer, Verifier};
let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

// Generate key pair and signature
let (pk1, sk) = ml_dsa_87::try_keygen()?;  // Generate both public and secret keys
let sig = sk.try_sign(&message, &[])?;  // Use the secret key to generate a message signature

// Serialize then send the public key, message and signature
let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), message, sig);
let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);

// Deserialize the public key and signature, then verify the message
let pk2 = ml_dsa_87::PublicKey::try_from_bytes(pk_recv)?;
let v = pk2.verify(&msg_recv, &sig_recv, &[]); // Use the public to verify message signature
assert!(v);
    
// Note that the last argument to sign() and verify() is the (NIST specified) context
// value which is typically empty for basic signature generation and verification.


*/