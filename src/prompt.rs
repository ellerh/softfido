
use pinentry_rs;
use std::sync::mpsc::{Receiver};
use secstr;

#[allow(dead_code)]
fn ttyname(fd: libc::c_int) -> Result<String, std::io::Error> {
    let mut buffer = vec![0x0u8; 80];
    let ptr = buffer.as_mut_ptr() as *mut i8;
    match unsafe { libc::ttyname_r(fd, ptr, buffer.len()) } {
        0 => {
            let end = buffer.iter().position(|&c| c == 0).unwrap();
            Ok(std::str::from_utf8(&buffer[..end]).unwrap().to_string())
        }
        err => Err(std::io::Error::from_raw_os_error(err)),
    }
}

fn escape_string(s: &str) -> String {
    let mut r = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => r.push_str("%0A"),
            c => r.push(c)
        }
    };
    r
}

pub fn yes_or_no_p(prompt: &str)
                  -> Receiver<Result<bool, pinentry_rs::Error>> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let escaped = escape_string(prompt);
    std::thread::spawn(move || {
        let peb = pinentry_rs::pinentry().description(escaped);
        let r = peb.confirm_yes_no();
        sender.send(r)//.unwrap()
    });
    receiver
}

pub fn read_pin(prompt: &str) -> Result<secstr::SecStr, pinentry_rs::Error> {
    pinentry_rs::pinentry()
        .description(escape_string(prompt))
        .pin("".to_string())
}
