// Test for connecting to postgresql database using tokio_postgres crate

use tokio_postgres::{NoTls, Error};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let (client, connection) =
        tokio_postgres::connect("host=localhost user=vehicle password=obdvehicle port=5468 dbname=demo_odb", NoTls).await?;

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    println!("Connected to the database!");

  
    // insert a row into the captures table:
    let insert_query = "INSERT INTO captures (vehicle, epoch, speed, speed_unit ) VALUES ('AZ40EUA', 1687000000, 60, 'mph' )";
    client.execute(insert_query, &[]).await?;

    // Select from the captures table:

    let query = "SELECT * FROM captures";
    let rows = client.query(query, &[]).await?;
    for row in rows {
        for i in 0..row.len() {
            let textvalue: Result<String, _> = row.try_get(i);
            match textvalue {
                Ok(val) => println!("Column {} value: {}", i, val),
                Err(_) => // If the value is not a string, try to get it as an integer
                {
                    let intvalue: Result<i32, _> = row.try_get(i);
                    match intvalue {
                        Ok(val) => println!("Column {} value: {}", i, val),
                        Err(_) => println!("Column {} value: <non-string, non-integer>", i),
                    }
                }
            }
        }
        
    }

    Ok(())
}
