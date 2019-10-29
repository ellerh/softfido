extern crate packed_struct;
extern crate serde_cbor;
extern crate pkcs11;
extern crate crypto as rust_crypto;

#[macro_use] extern crate packed_struct_codegen;
//#[macro_use] extern crate serde;
//use packed_struct::PackedStruct;

// #[macro_use]
// extern crate bitflags;

use std::net::{TcpListener, TcpStream};
use std::error::{Error};
// use std::io::Read;
// use std::io::BufReader;

//use std::convert::TryFrom;

#[macro_use]
mod macros;
#[macro_use]
mod prompt;

mod usbip;
mod hid;
mod ctaphid;
mod eventloop;
mod crypto;

use usbip::bindings as c;

struct Args {
    //arg0: String,
    pkcs11_module: String,
    token_label: String,
}

fn main() {
    let args = parse_args();
    let token = match crypto::open_token(
        std::path::Path::new(&args.pkcs11_module),
        &args.token_label) {
        Ok(x) => x,
        Err(err) => panic!("Failed to open token: {}", err)
    };
    let listener = TcpListener::bind("192.168.178.22:3240").unwrap();
    println!("USBIP Testserver");
    for s in listener.incoming() {
        println!("New connection {:?}\n", s);
        handle_stream(&mut s.unwrap(), &token).unwrap();
    }
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut r = Args {
        pkcs11_module: "/usr/lib/softhsm/libsofthsm2.so".to_string(),
        token_label: "softfido".to_string(),
    };
    fn req (arg: Option<String>, name: &str) -> String {
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
                },
                "--token-label" => {
                    r.token_label = req(args.next(), "--token-label");
                },
                x => panic!("Invalid argument: {}", x),
            }
        }
    }
}

fn handle_stream (stream: &mut TcpStream, token: &crypto::KeyStore)
                  -> Result<(), Box<Error>> {
    stream.set_nodelay(true)?;
    let (version, code, status) = usbip::read_op_common(stream)?;
    match (version, code as u32, status) {
        (usbip::USBIP_VERSION, c::OP_REQ_DEVLIST, 0) => {
            println!("OP_REQ_DEVLIST");
            usbip::write_op_rep_devlist (stream)?;
            stream.shutdown(std::net::Shutdown::Both)?
        },
        (usbip::USBIP_VERSION, c::OP_REQ_IMPORT, 0) => {
            println!("OP_REQ_IMPORT");
            let busid = usbip::read_busid(stream)?;
            println!("busid: {}", busid);
            if busid != "1-1" {
                panic!("Invalid busid: {}", busid)
            }
            usbip::write_op_rep_import (stream)?;
            println!("import request busid {} complete", busid);
            handle_commands(stream, token)?
        },
        _ =>
            panic!("Unsupported packet: \
                    version: 0x{:x} code: 0x{:x} status: 0x{:x}",
                   version, code, status),
    }
    Ok(())
}

fn handle_commands (stream: &mut TcpStream, token: &crypto::KeyStore)
                    -> Result<(), Box<Error>> {
    let mut dev = usbip::Device::new(token);
    let mut el = eventloop::EventLoop::new(&mut dev);
    usbip::Device::init_callbacks(&mut el);
    el.handle_commands(stream)
}
