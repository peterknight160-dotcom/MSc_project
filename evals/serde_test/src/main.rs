// Program to have a play around with the serde formatter

use serde::{Deserialize, Serialize};
use serde_json::Result;

#[derive(Serialize, Deserialize, Debug)]
struct Payload {

    name: String ,
    data: Vec<u8>

}

fn main() ->Result<()>{
    let my_payload = Payload {
        name:  String::from ("This is my name"),
        data: vec! [1u8;10],
    }; 
    println!("my_payload is {:?}", my_payload);

    let j =  serde_json::to_string(&my_payload).unwrap();
    println!("J is {:?}", j);

    let unpacked:Payload = serde_json::from_str(&j).unwrap();

    println!("Unpacked is {:?}", unpacked);


    Ok(())

}
