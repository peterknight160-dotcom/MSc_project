

use std::fs::File;
use std::time::{ SystemTime, UNIX_EPOCH};

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
   
        hashmap_to_json_set_epoch(x.clone());
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
 fn hashmap_to_json_set_epoch ( hash: BTreeMap<String, String>) -> String {
    
    let mut result= String::from("{\n");
    let mut first_element: bool = true;
    let mut hash_iter = hash.iter() ;

    while let Some ((key, value)) = hash_iter.next()  {
    
        let value_is_text  =! value.parse::<f64> ().is_ok();
         match first_element {
                true => { first_element = false}, 
                false => { result = result + ",\n"}

            }
        if key.ends_with("_unit") {
            let mut element: String=  "    \"".to_owned()  + key.strip_suffix("_unit").unwrap_or(key) + "\": {\n";
            element = element+  "        \"unit\": \"" + &value + "\",\n";
            if let Some ((_, value1 )) = hash_iter.next() {
       
               element = element +   "        \"value\": " + value1 + "\n    }";
            }
            result += &element; 


        }
        else {
            // Regular element
            // Handle default values
            let use_value = set_default_value(key, &value);

           
            let quote = String::from ("    \"");
            let mut element = quote + key + "\": ";
            if value_is_text {
                element = element + "\"" + &use_value + "\"" ;
            }
            else {
                element = element + &use_value 
            }
            result.push_str(&element);
            
        }
   


    }
    result += "\n}";

    println!("JSON String is {}", result);

    String::new ()
 }

 fn set_default_value ( key: &String,value: &String ) -> String{
    // Code to handle default values - mostly epoch
    let mut return_val = value.to_string();
    if key == "epoch" && value == "XXXX" {
        return_val= SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
        
        println!("Not now Joshepine");
    }
    return_val
 }
    

  


    
