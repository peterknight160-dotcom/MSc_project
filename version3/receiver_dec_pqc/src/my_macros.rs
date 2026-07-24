macro_rules! received_string {
    ($buffer:expr, $bytes_read:expr) => {{
        if $bytes_read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Nothing read",
            ));
        }

        String::from_utf8_lossy(&$buffer[..$bytes_read]).into_owned()
    }};
}

/* Usage


let received = received_string!(buffer, bytes_read);
do_stuff(received).await;



*/
