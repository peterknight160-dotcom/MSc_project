// Program to take a file name from the command line and print out three or more characters if they look like a string

pub fn main () {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <filename>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    // Need to be able to cope with non-UTF8 files, so we will read the file as bytes and then convert to string
    match std::fs::read(filename) {
        Ok(contents) => {
            let contents = String::from_utf8_lossy(&contents);
            for line in contents.lines() {
                if line.chars().count() >= 3 {
                    println!("{}", line);
                }
            }
        }
        Err(e) => {
            eprintln!("Error reading file {}: {}", filename, e);
            std::process::exit(1);
        }
    }
    
}