use std::io::{self, Error, ErrorKind};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use postcard;


use std::sync::Arc;
use std::time::Instant;



use serde::{Deserialize, Serialize};
//use serde_json::Result;




#[derive(Serialize, Deserialize)]
struct Ping {
    SequenceNumber : u64,
}

