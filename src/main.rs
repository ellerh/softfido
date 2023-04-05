// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

use softfido::{crypto::Pin, crypto::Token, prompt, usbip};
use std::net::TcpListener;

struct Args {
    pkcs11_module: String,
    token_label: String,
    pin_file: Option<String>,
}

fn main() {
    let args = parse_args();
    let token = Token::new(
        &args.pkcs11_module,
        args.token_label.as_ref(),
        args.pin_file
            .map_or(Pin::Ask(Box::new(prompt::read_pin)), Pin::File),
    )
    .unwrap_or_else(|e| panic!("Failed to open token: {}", e));
    let listener = TcpListener::bind("127.0.0.1:3240").unwrap();
    //let listener = TcpListener::bind("0.0.0.0:3240").unwrap();
    println!("Softfido server is listening.");
    usbip::start_server(&listener, token, Box::new(prompt::Pinentry {}))
}

fn default_args() -> Args {
    Args {
        pkcs11_module: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
        token_label: "softfido".to_string(),
        pin_file: None,
    }
}

fn print_usage() {
    let defaults = default_args();
    println!(
        r"USAGE: {prog} [OPTIONS]
OPTIONS:
  --help                   Print help information
  --token-label <LABEL>    Use LABEL to find the crypto token
                             [{label}]
  --pkcs11-module <LIB>    Load LIB to access the PCKC11 store 
                             [{lib}]
  --pin-file <FILE>        Read gpg encryped User-PIN from FILE
                             [{pinfile:?}]",
        prog = std::env::args().next().unwrap_or("<progname>".into()),
        label = defaults.token_label,
        lib = defaults.pkcs11_module,
        pinfile = defaults.pin_file
    )
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut r = default_args();
    fn req(arg: Option<String>, name: &str) -> String {
        match arg {
            Some(s) => s,
            None => panic!("Option {} requires argument", name),
        }
    }
    loop {
        match args.next() {
            None => return r,
            Some(s) => match s.as_str() {
                "--pkcs11-module" => {
                    r.pkcs11_module = req(args.next(), "--pkcs11-module");
                }
                "--token-label" => {
                    r.token_label = req(args.next(), "--token-label");
                }
                "--pin-file" => {
                    r.pin_file = Some(req(args.next(), "--pin-file"));
                }
                "--help" => {
                    print_usage();
                    std::process::exit(0)
                }
                x => panic!("Invalid argument: {}", x),
            },
        }
    }
}
