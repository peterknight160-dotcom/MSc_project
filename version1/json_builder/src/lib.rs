use std::f16::consts::EULER_GAMMA;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::collections::BTreeMap;
use std::collections::HashMap;


pub fn file_to_json(filename: &str) -> String {
    // This is the main code for building the JSON file
    // It will read from the input files, process the data, and write to the output JSON file

    // First job, open the input file and read it line by line
    let file = File::open(filename).expect("Could not open file");  
    let reader = BufReader::new(file);
    let mut column_mapping: HashMap<usize, String> = HashMap::new();
    let mut data: Vec<BTreeMap<String, String>> = Vec::new();
           
    for (i, line) in reader.lines().enumerate() {
        let line = line.expect("Could not read line");
        if i == 0 {
            // This is the header line, so build the name/position mapping struct here
            let headers: Vec<&str> = line.split(',').collect();
            for (index, header) in headers.iter().enumerate() {
                column_mapping.insert(index, header.trim().to_string());
            }
            continue;
        }
        // Process the line and extract the relevant data
        data.push( BTreeMap::new());
        let parts: Vec<&str> = line.split(',').collect();
      
       
        for (j, part) in parts.iter().enumerate() {
           
            if let Some(header) = column_mapping.get(&j) {
              
                data[i-1].insert(header.clone(), part.trim().to_string());
            }
        }
        
        
    }   
    for x in data.iter() {
        println! (" row is {:?}\n", x);
        hashmap_to_json(x.clone());
    }
    //println !("{:?}", data);     
    String::new()
}

// Function to convert a hashmap to a JSON document.


/* Fragment of JSON 

    "altitude": {
        "unit": "m",
        "value": 46
    },
    "latitude": -3.520429,
    "longitude": -58.321307,
    
    */
 fn hashmap_to_json ( hash: BTreeMap<String, String>) -> String {
    
    let mut result= String::from("{ ");
    for (key,value ) in hash.iter() {
        let value_is_text  =! value.parse::<f64> ().is_ok();
        if key.ends_with("_unit") {
            // 
            println!("Key is {}, Ignore for now",key);

        }
        else {
            let quote = String::from ("\"");
            let mut element = quote + key + "\": ";
            if value_is_text {
                element = element + String::from ("\"") + value + "\"";
            }
            else {
                element = 
            }
            
        }

    }



    String::new ()
 }
    

    /* 
    for (key, value) in hash.iter()
    { 
        // If element is of type unit

        if key.ends_with("_unit") {
            // Handle this
            println! ("Ignore _unit for now");
        }
        else {
            let  quote = String::from ("\"");
            let mut json_element = quote + &key + "\": " ;
           
           }
            
            println! ("json_element is {}", json_element);
            
            
        }

    } */



    
