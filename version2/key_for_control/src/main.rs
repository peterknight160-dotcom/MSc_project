// Program to run as a one-off for the control planes's key generation.

// Generates ML_KEM_87 key for signing it's own output
// Generates an AES256 key for encrypting it't output.



use dilithium::{ ML_DSA_87, MlDsaKeyPair};
use base65::base64_from_bytes;

const DIGITS: &str = "1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679";
#[allow(non_camel_case_types)]
struct myMLDSAKeyPair {
    pub private_key: String ,
    pub public_key: String 
}

 fn gen_ml_dsa_key_pair() -> Option <myMLDSAKeyPair> {

   let kp = MlDsaKeyPair::generate(ML_DSA_87).unwrap();
   let private_key = base64_from_bytes( kp.private_key())?;
   let public_key = base64_from_bytes (kp.public_key())?;

  Some (myMLDSAKeyPair {
    private_key,
    public_key
  })

}

fn gen_aes256_key () -> Option <String> {
    let mut round1  =vec![0u8; 32];
    let  digits = String::from( DIGITS);


    for i in 0..32 {
        let chars = String::from (& digits [ i*3..i*3+3]);

        let n = chars.parse::<u16>().unwrap() ;
         round1[i] = n as u8 ;

        
    }



    Some(base64_from_bytes (&round1)?)
}


fn main (){
    let key_strings = gen_ml_dsa_key_pair().unwrap();

    println!( "Private Key is {} ", key_strings.private_key);
    println!( "Publie Key is {} ", key_strings.public_key);
    println! (" AES256 key is {} ", gen_aes256_key().unwrap());
}

