use std::io::{self, Read, Write,Error,ErrorKind};

use std::net::{TcpListener,TcpStream};

fn main()   {
    let addr = "127.0.0.1:8080";
    println!("Read from stream {:?}", read_from_stream(addr) );
}


pub fn read_from_stream (addr : &str ) -> Result <String,io::Error>{


  let listener = TcpListener::bind(addr)?;
    let (mut socket, remote_addr) = listener.accept()?;
    let mut buffer = [0u8;1000];

    println!(" remote_addr is {} ", remote_addr);
    let bytes_read= socket.read(& mut buffer )?;

    if bytes_read >0  {
        return  Ok(String::from_utf8_lossy(&buffer[..bytes_read]).to_string());
    }
    else {
        return  Err( Error::new(ErrorKind::Other, "Nothing read"));
}
}