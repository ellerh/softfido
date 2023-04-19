use std::fmt::Write;

pub fn hex(s: &[u8]) -> String {
    let mut r = String::with_capacity(2 * s.len());
    for byte in s {
        write!(r, "{:02X}", byte).unwrap();
    }
    r
}
