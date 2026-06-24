
// Implement the receiver

use core_utils::*;
use std::io::Read;
use std::net::TcpListener;
const ADDR: &str ="127.0.0.1:8080";


fn main() {


    let signature_keys = get_keys_from_control( ADDR);  // Step 2 in the flow
    // Now do stuff with them 
    
    println!( "Have both keys, ready to rock and roll"); 
           
        let ml_kem_keys = generate_ml_kem_keys (& signature_keys , &stream); // Step 4 

        let shared_key = generate_shared_keys ( &ml_kem_keys, &signature_keys , &stream)  ;  //Step 6

        ready_to_send ( & signature_keys ,&stream) ;  // Step 7

        let data_object = receive_data ( & shared_key, &stream);
  
    }



    Ok(())
}
