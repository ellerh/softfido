use softfido::{crypto, usbip};
use std::net::TcpListener;

type R<T> = Result<T, Box<dyn std::error::Error>>;

fn main() {
    let token = crypto::Token::open(
        "/usr/lib/softhsm/libsofthsm2.so",
        "test-softfido",
        crypto::Pin::String(String::from("fedcba").into()),
    )
    .unwrap_or_else(|e| panic!("Failed to open token: {}", e));
    //let listener = TcpListener::bind("127.0.0.1:3240").unwrap();
    let listener = TcpListener::bind("0.0.0.0:3240").unwrap();
    println!("Softfido server is listening.");
    usbip::start_server(&listener, token, yes_or_no_p)
}

fn yes_or_no_p(prompt: &str) -> R<bool> {
    let c = |pat| prompt.contains(pat);
    if c("timeout.com") {
        std::thread::sleep(std::time::Duration::from_millis(200));
        Err("timed out".into())
    } else if c("timeout2.com") {
        std::thread::sleep(std::time::Duration::from_millis(400));
        Err("timed out".into())
    } else if (c("test-deny-credentials") && c("registration credentials"))
        || (c("test-deny-challenge") && c("signing challenge"))
    {
        Ok(false)
    } else if c("test-close-window") && c("registration credentials") {
        Err("window closed".into())
    } else {
        Ok(true)
    }
}
