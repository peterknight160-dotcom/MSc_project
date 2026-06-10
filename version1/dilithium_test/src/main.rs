use dilithium::{MlDsaKeyPair, ML_DSA_44};
use std::time::Instant;

fn check_fips204(message: &[u8], iterations: usize) -> Option<bool> {
    println!("Message length: {:?}", message.len());

    // Generate key pair and signature

    let kp = MlDsaKeyPair::generate(ML_DSA_44).unwrap();

    let start_keygen = Instant::now();

    for _ in 0..iterations {
        let _ = MlDsaKeyPair::generate(ML_DSA_44).ok();
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
        let _ = kp.sign(&message, &[]).unwrap(); // Use the secret key to generate a message signature
        //dump.push(sig.unwrap()[0]);
    }
    let step2 = start_sign.elapsed();
    println!("Generating signature took {:.2?} in total", step2);
    println!(
        "Generating signature took {:.2?} per signature",
        step2 / iterations as u32
    );
  

    let sig = kp.sign(&message, &[]).unwrap();



    let start_verify = Instant::now();

    for _ in 0..iterations {
          let _ = MlDsaKeyPair::verify(    kp.public_key(), &sig,    message, b"",    ML_DSA_44);
    }
    let step3 = start_verify.elapsed();
    println!("Verifying signature took {:.2?} in total", step3);
    println!(
        "Verifying signature took {:.2?} per signature",
        step3 / iterations  as u32
    );

    let v = MlDsaKeyPair::verify(kp.public_key(), &sig, message, b"", ML_DSA_44); // Use the public to verify message signature
    Some(v)
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

    if check_fips204(&message, iterations).unwrap() {
        println!("Validation is good");
    }
}

