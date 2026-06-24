


use core_utils::*;


fn main() -> std::io::Result<()> {


    let signature_keys = get_keys_from_control( "127.0.0.1:8080");
    // Now do stuff with them 

    println!( "Have both keys, ready to rock and roll"); 



    Ok(())
}
