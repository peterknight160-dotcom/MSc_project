

fn main() {
    println!("Base64 encoder");

    let input = "foob";
    if let Some(encoded) = base65::base64_from_str(input) {
        println!("Encoded: {}", encoded);
    } else {
        println!("Failed to encode");
    }

 let input2 = String::from("Hello, world2!,");
    if let Some(encoded) = base65::base64_from_str(&input2) {
        println!("Encoded: {}", encoded);
    } else {
        println!("Failed to encode");
    }
 let input3 = [9u8; 14];
    let input3_str = std::str::from_utf8(&input3).unwrap();
    if let Some(encoded) = base65::base64_from_str(input3_str) {
        println!("Encoded: {}", encoded);
    } else {
        println!("Failed to encode");
    }

    let input4 = "Zm9vYg==";
    
    if let Some(decoded) = base65::base64_to_bytes(input4) {
        println!("Decoded: {:?}", &std::str::from_utf8(&decoded).unwrap());
    } else {
        println!("Failed to decode");
    }

   
}


