// Implement the receiver


use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
struct Ping {
    sequence_number: u64,
}






//use std::collections:: HashSet;

use std::io::{Error, ErrorKind};
use std::time::SystemTime;
//use std::result;
//use serde::{Deserialize, Serialize};
use ::std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;



#[tokio::main]
async fn main() -> std::io::Result<()> {
     // Get the two addreess from the command line arguments
    let args: Vec<String> = std::env::args().collect();
      if args.len() != 4 {
        println!("\n\n\n Usage: {} <client_addr> <receiver_addr> <receiver_addr_control>", args[0]);
        println!("Example: {} 127.0.0.1:8080 127.0.0.1:8090 127.0.0.1:8095\n\n\n", args[0]);
        return Err(Error::new(
            ErrorKind::Other,
            "Invalid number of arguments",
        ));
    }

    let _client_addr = &args[1];
    let receiver_addr = &args[2];
    let receiver_addr_control = &args[3];



 

    let listener_result = TcpListener::bind(receiver_addr).await;
    if listener_result.is_err() {
        eprintln!(
            "Failed to bind to {}: {}",
            receiver_addr,
            listener_result.unwrap_err()
        );
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to bind to receiver address",
        ));
    }
    let listener = listener_result.unwrap();
    //println!("Echo server running on {}", receiver_addr);

    //let (tx, mut rx) = mpsc::channel::<()>(1);

    loop {
     
        
        tokio::select! {
     

            Ok((socket, _addr)) = listener.accept() => {

        
        
                tokio::spawn(async move {

                    if let Err(_e) = handle_connection(socket).await {
                        //eprintln!("Error handling {}: {}", addr, e);
                        ()
                    }
                });
            }
        }
    }
}

async fn handle_connection(
    mut socket: TcpStream,

  
) -> std::io::Result<()> {
    // Step 3  - Got connection request from client
    //Read the length and body of the request from the client
    let len = socket.read_u32().await?;

    let mut buffer = vec![0; len as usize];
    let _bytes_read = socket.read_exact(&mut buffer).await?;

    // Send it straight back to the client
 

    socket.write_u32(buffer.len() as u32).await?;
    socket.write_all(&buffer).await?;

  

    Ok(())
}

