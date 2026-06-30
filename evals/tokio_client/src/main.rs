use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;

    let mut msg = String::from("start");

    for i in 0..5 {
        println!("A -> B: {}", msg);
        stream.write_all(msg.as_bytes()).await?;

        let mut buf = vec![0; 1024];
        let n = stream.read(&mut buf).await?;
        let reply = String::from_utf8_lossy(&buf[..n]);

        println!("A <- B: {}", reply);

        msg = format!("reply {} from A", i);
    }

    Ok(())
}