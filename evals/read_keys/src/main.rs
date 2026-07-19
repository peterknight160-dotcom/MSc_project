use base65::*;
use std::io::BufRead;

fn main() {
   // Open file 
        let mut signature_keys = Vec::new();
   if let Ok(lines) = read_lines("./keys_generated.txt") {
        // Consumes the iterator, returns an (Optional) String
        for line in lines.map_while(Result::ok) {
            let key = base64_to_bytes(&line).unwrap();
            let len = key.len();
            println!("Key: {:?} (length: {})", key, len);
            signature_keys.push(key);
            
        }
    }
    println!("===============================================================");
    for key in signature_keys {
        println!("Key: {:?}", key);
    }
}


/// Reads lines from a file and returns an iterator over the lines.
pub fn read_lines<P>(filename: P) -> std::io::Result<std::io::Lines<std::io::BufReader<std::fs::File>>>
where
    P: AsRef<std::path::Path>,
{
    let file = std::fs::File::open(filename)?;
    Ok(std::io::BufReader::new(file).lines())
}
