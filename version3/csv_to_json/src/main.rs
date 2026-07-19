use csv::StringRecord;

const JSON_FILE: &str = "JSON.csv";
use std::time::{SystemTime, UNIX_EPOCH};

use std::fs::File;
use std::io::{self, BufRead,Write};
use std::path::Path;

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn main() -> std::io::Result<()> {
    //  let mut json_reader = CsvReader::set_up("JSON.csv").unwrap();
    let mut skip = false;
    let mut json_reader = CsvReader::set_up("JSON.csv").unwrap();
    let headers = json_reader.headers().clone();

    // Create an output file to write the JSON documents to
    let output_file = File::create("JSON.txt").expect("Unable to create output file");


    loop {
        if !skip {
            let line = json_reader.next().unwrap().unwrap();
            let json_doc_to_send = json_doc_from_reader(line, &headers, "AV40AEU");

            println!("JSON document to send: {}", json_doc_to_send);
            // Write the JSON document to the output file
            writeln!(&output_file, "{}", json_doc_to_send).expect("Unable to write to output file");
        }
        let input =
            get_input("What would you like to proceses another entry? (YES/NO))").to_uppercase();

        match input.as_str() {
            "END" | "NO" | "N" | "E" => break,
            "YES" | "Y" | "AYE" => (),
            _ => {
                skip = true;
            }
        };
    }

    // Wait for 100ms
    std::thread::sleep(std::time::Duration::from_millis(100));

    Ok(())
}

fn get_input(prompt: &str) -> String {
    let mut input = String::new();
    println!("{}", prompt);

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    // Remove any trailing whitespace
    input.trim_end().to_string()
}

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

pub fn json_doc_from_reader(
    line: StringRecord,
    headers: &StringRecord,
    vehicle_id: &str,
) -> String {
    let mut result = String::from("{ ");
    let mut first_element: bool = true;

    // Zip the headers and line together to create a HashMap
    let mut hash_iter = headers.iter().zip(line.iter());

    while let Some((key, value)) = hash_iter.next() {
        // Replace value = (null) with null
        let value = if value == "(null)" { "null" } else { value };

        match first_element {
            true => first_element = false,
            false => result = result + ", ",
        }
        if key.ends_with("_unit") {
            let mut element: String =
                "    \"".to_owned() + key.strip_suffix("_unit").unwrap_or(key) + "\": { ";
            element = element + "        \"unit\": \"" + &value + "\", ";
            if let Some((_, value1)) = hash_iter.next() {
                // Replace value = (null) with null
                let value1 = if value1 == "(null)" { "0" } else { value1 };

                element = element + "        \"value\": " + value1 + "     }";
            }
            result += &element;
        } else {
            // Regular element
            // Handle default values
            let use_value = set_default_value(key, &value, vehicle_id);

            let quote = String::from("    \"");
            let mut element = quote + key + "\": ";
            let value_is_text = !use_value.parse::<f64>().is_ok();
            if value_is_text {
                element = element + "\"" + &use_value + "\"";
            } else {
                element = element + &use_value
            }
            result.push_str(&element);
        }
    }
    result += " }";

    result
}

fn set_default_value(key: &str, value: &str, vehicle_id: &str) -> String {
    // Code to handle default values - mostly epoch
    let mut return_val = value.to_string();
    if key == "epoch" && &value[0..4] == "XXXX" {
        return_val = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
    }
    if key == "vehicle_id" {
        return_val = vehicle_id.to_string();
    }
    return_val
}
