use  rand::*; 
use base65::base64_from_bytes;
fn main() {
    let nonce = generate_nonce();
    println!("{:?}", nonce);
    let base65 = base64_from_bytes(&nonce).unwrap();
    println!("{} and {} long", base65, base65.len());
}
pub fn generate_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; 32];
    rand::rng().fill(&mut nonce[..]);
    nonce
}
