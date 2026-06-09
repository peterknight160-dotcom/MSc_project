use ml_dsa::{MlDsa44, Generate, Keypair, SigningKey, Signer, Verifier};
use std::time::Instant;

fn check_fips204(message: &[u8], iterations: usize) {
    println!("Message length: {:?}", message.len());

    // Generate key pair and signature
let sk = SigningKey::<MlDsa44>::generate();
let vk = sk.verifying_key();



    //Generate both public and secret keys

    let start_keygen = Instant::now();
    let start_keygen_cycle = read_timer();
    for _ in 0..iterations {
        let sk = SigningKey::<MlDsa44>::generate();
    let _vk = sk.verifying_key();

    }
    let end_keygen_cycle = read_timer();
    let step0 = start_keygen.elapsed();
    println!("Key generation took {:.2?} in total", step0);
    println!(
        "Key generation took {:.2?} per iteration",
        step0 / iterations as u32
    );
    println!(
        "Key generation took {} cycles in total",
        end_keygen_cycle - start_keygen_cycle
    );
    println!(
        "Key generation took {} cycles per iteration",
        (end_keygen_cycle - start_keygen_cycle) / iterations as u64
    );

    let start_sign = Instant::now();
    // let mut dump = Vec::new();
    let start_sign_cycle = read_timer();
    for _ in 0..iterations {
    let _ = sk.sign(message);
    }
    let step2 = start_sign.elapsed();
    println!("Generating signature took {:.2?} in total", step2);
    println!(
        "Generating signature took {:.2?} per signature",
        step2 / iterations as u32
    );
    let end_sign_cycle = read_timer();
    println!(
        "Generating signature took {} cycles in total",
        end_sign_cycle - start_sign_cycle
    );
    println!(
        "Generating signature took {} cycles per signature",
        (end_sign_cycle - start_sign_cycle) / iterations as u64
    );
    let sig = sk.sign(message);
    
    let start_verify = Instant::now();
    let start_verify_cycle = read_timer();
    for _ in 0..iterations {
        let _ = vk.verify(message, &sig);
    }
    let step3 = start_verify.elapsed();
    println!("Verifying signature took {:.2?} in total", step3);
    println!(
        "Verifying signature took {:.2?} per signature",
        step3 / iterations  as u32
    );
    let end_verify_cycle = read_timer();
    println!(
        "Verifying signature took {} cycles in total",
        end_verify_cycle - start_verify_cycle
    );
    println!(
        "Verifying signature took {} cycles per signature",
        (end_verify_cycle - start_verify_cycle) / iterations as u64
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

mod imp {
    #[cfg(target_arch = "x86_64")]
    pub fn read() -> u64 {
        let t: u64;
        unsafe {
            core::arch::asm!(
                "rdtscp",
                "shl rdx, 32",
                "or rax, rdx",
                out("rax") t,
                out("rdx") _,
            );
        }
        t
    }

    #[cfg(target_arch = "aarch64")]
    pub fn read() -> u64 {
        let t: u64;
        unsafe {
            core::arch::asm!(
                "isb",
                "mrs {0}, cntvct_el0",
                out(reg) t,
            );
        }
        t
    }
}

pub fn read_timer() -> u64 {
    imp::read()
}
