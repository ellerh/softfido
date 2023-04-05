use softfido::{crypto, prompt, usbip};
use std::net::TcpListener;
use std::sync::mpsc::Receiver;

fn main() {
    let token = crypto::Token::new(
        "/usr/lib/softhsm/libsofthsm2.so",
        "test-softfido",
        crypto::Pin::String(String::from("fedcba").into()),
    )
    .unwrap_or_else(|e| panic!("Failed to open token: {}", e));
    //let listener = TcpListener::bind("127.0.0.1:3240").unwrap();
    let listener = TcpListener::bind("0.0.0.0:3240").unwrap();
    println!("Softfido server is listening.");
    usbip::start_server(&listener, token, Box::new(ConfirmTests {}))
}

struct ConfirmTests {}

impl prompt::Prompt for ConfirmTests {
    fn yes_or_no_p(&self, prompt: &str) -> Receiver<Result<bool, String>> {
        let timeout_test = prompt.contains("Please don't confirm");
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            if timeout_test {
                std::thread::sleep(std::time::Duration::from_secs(20));
                Ok(())
            } else {
                sender.send(Ok(true))
            }
        });
        receiver
    }
}
