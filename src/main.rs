extern crate packed_struct;
extern crate rand;

#[macro_use] extern crate packed_struct_codegen;
//use packed_struct::PackedStruct;

// #[macro_use]
// extern crate bitflags;

use std::net::{TcpListener, TcpStream};
use std::error::{Error};
// use std::io::Read;
// use std::io::BufReader;

use std::convert::TryFrom;
    
mod usbip;

fn main() {
    let listener = TcpListener::bind("192.168.178.22:3240").unwrap();
    println!("USBIP Testserver");
    for s in listener.incoming() {
        println!("New connection {:?}\n", s);
        handle_stream(&mut s.unwrap()).unwrap();
    }
}

fn handle_stream (stream: &mut TcpStream) -> Result<(), Box<Error>> {
    stream.set_nodelay(true)?;
    let (version, code, status) = usbip::read_op_common(stream)?;
    match (version, code as u32, status) {
        (usbip::USBIP_VERSION, usbip::OP_REQ_DEVLIST, 0) => {
            println!("OP_REQ_DEVLIST");
            usbip::write_op_rep_devlist (stream)?;
            stream.shutdown(std::net::Shutdown::Both)?
        },
        (usbip::USBIP_VERSION, usbip::OP_REQ_IMPORT, 0) => {
            println!("OP_REQ_IMPORT");
            let busid = usbip::read_busid(stream)?;
            println!("busid: {}", busid);
            if busid != "1-1" {
                panic!("Invalid busid: {}", busid)
            }
            usbip::write_op_rep_import (stream)?;
            println!("import request busid {} complete", busid);
            handle_commands(stream);
        },
        _ =>
            panic!("Unsupported packet: \
                    version: 0x{:x} code: 0x{:x} status: 0x{:x}",
                   version, code, status),
    }
    Ok(())
}

fn handle_commands (stream: &mut TcpStream) -> Result<(), Box<Error>> {
    let mut dev = usbip::Device::new();
    loop {
        let header = usbip::read_cmd_header (stream)?;
        println!("header.base: {:?}", &header.base);
        match u32::from_be(header.base.command) {
            usbip::USBIP_CMD_SUBMIT => {
                println!("CMD_SUBMIT: \n");
                handle_submit(&mut dev, stream, &header)?
            },
            usbip::USBIP_CMD_UNLINK => {
                println!("CMD_UNLINK: \n");
                panic! ("CMD_UNLINK nyi")
            },
            cmd => panic! ("Unsupported command: {}", cmd)
        }
    }
}

fn handle_submit (dev: &usbip::Device, stream: &mut TcpStream,
                     header: &usbip::usbip_header)
                     -> Result<(), Box<Error>> {
    //let devid = u32::from_be(header.base.devid);
    //let devnum = u16::try_from(devid & 0xffff)?;
    //let busnum = u16::try_from(devid >> 16)?;
    let endpoint = u8::try_from(u32::from_be(header.base.ep))?;
    // let direction = match u32::from_be(header.base.direction) {
    //     usbip::USBIP_DIR_OUT => false,
    //     usbip::USBIP_DIR_IN => true,
    //     dir => panic!("Invalid direction: {}", dir)
    // };
    // println!("busnum: {} devnum: {} ep: {} direction: {}",
    //          busnum, devnum, ep, direction);
    let cmd = unsafe{ header.u.cmd_submit };
    // println!("cmd: {:?}", cmd);
    //let transfer_flags = u32::from_be(cmd.transfer_flags);
    let transfer_buffer_length =
        usize::try_from(i32::from_be(cmd.transfer_buffer_length))
        .unwrap();
    // println!("transfer_flags: {} {:?}\n\
    //           transfer_buffer_length: {}\n\
    //           start_frame: {}\n\
    //           number_of_packets: {}\n\
    //           interval: {}\n\
    //           setup: {:?}",
    //          transfer_flags,
    //          usbip::TranfserFlags::unpack(&transfer_flags.to_be_bytes())
    //          .unwrap(),
    //          transfer_buffer_length,
    //          i32::from_be(cmd.start_frame),
    //          i32::from_be(cmd.number_of_packets),
    //          i32::from_be(cmd.interval),
    //          cmd.setup);
    let v = Vec::<u8>::with_capacity(transfer_buffer_length);
    let mut buf = std::io::Cursor::new(v);
    match dev.process_request (endpoint, &cmd.setup, &mut buf, stream) {
        Ok(()) => {
                let v = buf.into_inner();
                let rep = v.as_slice();
                usbip::write_submit_reply(
                    stream, header,
                    &rep[.. std::cmp::min(transfer_buffer_length, rep.len())])?
            },
            Err(err) => {
                println!("Request Error: {:?}",  err);
                usbip::write_submit_reply_error(stream, header)?
            }
    }
    Ok(())
}
