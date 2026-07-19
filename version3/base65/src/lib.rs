use std::time::{SystemTime };

// Coding my own base64
pub fn base64_from_bytes ( input : &[u8]) -> Option < String>
{
    let mut result = String::new();
    // Three input chars becomes 4 outputs
    let len = input.len();
    let groups = len /3 ;
    for i in 0..groups {
        // Convert Three bytes to 4 , 6 binary digits
        let start= i*3;
        let z = (input[start] as u32) << 16 | (input[start+1] as u32) << 8 | (input[start+2] as u32);
        for j in 0..4 {
            let index = (z >> (6*(3-j))) & 0x3F;
            let c = match index {
                0..=25 => (index + 'A' as u32) as u8 as char,
                26..=51 => (index - 26 + 'a' as u32) as u8 as char,
                52..=61 => (index - 52 + '0' as u32) as u8 as char,
                62 => '+',
                63 => '/',
                _ => return None,
            };
            result.push(c);
        }
    }
    if groups*3 < len {
        let remaining = len - groups*3;
        let mut z = 0u32;
        for j in 0..remaining {
            z |= (input[groups*3 + j] as u32) << (16 - 8*j);
        }
        for j in 0..(remaining + 1) {
            let index = (z >> (6*(3-j))) & 0x3F;
            let c = match index {
                0..=25 => (index + 'A' as u32) as u8 as char,
                26..=51 => (index - 26 + 'a' as u32) as u8 as char,
                52..=61 => (index - 52 + '0' as u32) as u8 as char,
                62 => '+',
                63 => '/',
                _ => return None,
            };
            result.push(c);
        }
        for _ in remaining+1..4 {
            result.push('=');
        }
    }


    Some (result)
}

pub fn  base64_from_str ( input : &str) -> Option < String>
{ 
    base64_from_bytes(input.as_bytes())
}


// Coding my own base64
pub fn base64_to_bytes ( input : &str) -> Option < Vec<u8>>
{
    let mut result  = Vec::new();
    // Break input into 4 character chunks
    let len = input.len();
    let groups = len /4 ;
    let mut padding = 0;
    // Convert each 4 character chunk to 3 bytes
    for i in 0..groups {
        let start= i*4;
        let mut z = 0u32;
        for j in 0..4 {
            let c = input.chars().nth(start+j).unwrap();
          
            let index = match c {
                'A'..='Z' => (c as u32) - ('A' as u32),
                'a'..='z' => (c as u32) - ('a' as u32) + 26,
                '0'..='9' => (c as u32) - ('0' as u32) + 52,
                '+' => 62,
                '/' => 63,
                '=' => {
                    padding += 1;
                    0
                },
                _ => return None,
            };
            
            z |= index << (6*(3-j));
            
        }
        for j in 0..3 {
            if j < 3 - padding {  // Padding only affects the last group, so we only add bytes if j is less than 3 - padding
                result.push(((z >> (8*(2-j))) & 0xFF) as u8);
            }
            
        }
    
    
    }
    // Remove padding bytes
   
    
    Some (result)
}

pub fn get_time_as_millis_base64() ->String{
    let now = SystemTime::now();
    let since_epoch = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    //since_epoch.as_millis().to_be_bytes().iter().filter(|x| **x >0).cloned().collect::<Vec<u8>>()
    let time = (since_epoch.as_millis() ).to_be_bytes().to_vec()[8..].to_vec();
   

   base64_from_bytes(&time).unwrap()
   
}
