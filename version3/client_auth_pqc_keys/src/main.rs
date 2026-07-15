use base65::*;
use core_utils_pqc::*;
const ADDR: &str = "127.0.0.1:8080";
const RECEIVER_ADDR: &str = "127.0.0.1:8090";
//const JSON_FILE: &str = "JSON.csv";

use kyber::ML_KEM_512;
use std::env;
use tokio::fs::OpenOptions;

use tokio::net::{TcpStream};
use tokio::io::{AsyncWriteExt};





#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Step 1
    let signature_keys = match get_keys_from_control(ADDR).await {
        Ok(v) => v,
        Err(e) => panic!(" Have not got a valid signature_keys, {}", e),
    };
    // Now do stuff with them

    println!("Have both keys, ready to rock and roll");

    // Sleep for a second to allow the receiver to start up
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Now to do the performance test

    let eloops = env::var("LOOPS").ok(); //Get result and convert option
    let nloops: u32;

    match eloops.is_some() {
        true => nloops = eloops.unwrap().parse::<u32>().unwrap(),
        false => nloops = 10,
    }
   
    // Open a file to write the keys generated to

    
   let mut file = OpenOptions::new()
        .create(true)  // create if it doesn't exist
        .append(true)  // append instead of overwrite
        .open("keys_generated.txt").await?;

   
   

    for i in 0..nloops {

        //Sleep for a 10ms second to allow the receiver to start up
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        println!("Loop {} of {}", i + 1, nloops);
   
        let mut stream = TcpStream::connect(RECEIVER_ADDR).await?;

        //Step 3



        let _s = match send_signed_rq(&signature_keys, &mut stream).await {
            Ok(v) => v,
            Err(_) => panic!("Failed to send keys, exiting"),
        };

        //Step 4

        //let s = get_ml_keys(&signature_keys, &mut stream).await;
        let pub_key = get_ml_keys(&signature_keys, &mut stream).await.unwrap();



        //Step 5

        let (ct, ss_sender) = kyber::safe_encaps(ML_KEM_512, pub_key.as_slice()).unwrap();
        let shared_secret = ss_sender.as_bytes();
        let ss_b64  = base64_from_bytes(shared_secret);

        if ss_b64.is_some () {
            // print the base64 encoded shared secret to the file
            println!("Base64 encoded shared secret: {}", ss_b64.as_ref().unwrap());
            let ss_b64_str = ss_b64.unwrap();
            
            file.write_all(ss_b64_str.as_bytes() ).await?;
            file.write_all(b"\n").await?;
          
        } else {
           println!("Failed to encode shared secret");
        }
        if i % 10 == 0 {
         file.flush().await?;
        }



        let _ = send_ciphertext(ct, &mut stream).await;
 

        

        // Disconnect from the receiver
        let _ = stream.shutdown().await;
    }

    //close the file
    let _ = file.shutdown().await;

   
   
    Ok(())
}


