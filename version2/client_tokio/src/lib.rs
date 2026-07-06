use std::fs::File;
use std::time::{ SystemTime, UNIX_EPOCH};
use csv::*;

pub struct CsvReader {
    headers: StringRecord,
    records: csv::StringRecordsIntoIter<File>,
}

impl CsvReader {
    pub fn set_up(path: &str) -> csv::Result<Self> {
        let mut rdr = csv::Reader::from_path(path)?;
        
        let headers = rdr.headers()?.clone();

        Ok(Self {
            headers,
            records: rdr.into_records(),
        })
    }

    pub fn headers(&self) -> &StringRecord {
        &self.headers
    }
        
}

impl Iterator for CsvReader {
    type Item = csv::Result<StringRecord>;

     fn next(&mut self) -> Option<Self::Item> {
        self.records.next() 
    }
}


// Function to convert a StringRecord to a JSON document.

 pub fn json_doc_from_reader ( line: StringRecord, headers: &StringRecord) -> String {
    
    let mut result= String::from("{\n");
    let mut first_element: bool = true;
    
    // Zip the headers and line together to create a HashMap
    let mut hash_iter = headers.iter().zip(line.iter());

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
    

    result
 }

 fn set_default_value ( key: &str, value: &str ) -> String{
    // Code to handle default values - mostly epoch
    let mut return_val = value.to_string();
    if key == "epoch" && value == "XXXX" {
        return_val= SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
        

    }
    return_val
 }
    

  
/*
struct Person {
    name: String,
    age: u32,
}

struct CsvReader {
    records: csv::StringRecordsIntoIter<File>,
}

impl CsvReader {
    fn set_up(path: &str) -> csv::Result<Self> {
        let rdr = csv::Reader::from_path(path)?;

        Ok(Self {
            records: rdr.into_records(),
        })
    }
}

impl Iterator for CsvReader {
    type Item = csv::Result<Person>;

    fn next(&mut self) -> Option<Self::Item> {
        self.records.next().map(|result| {
            let record = result?;

            Ok(Person {
                name: record[0].to_string(),
                age: record[1].parse().unwrap_or(0),
            })
        })
    }
}
*/
    
