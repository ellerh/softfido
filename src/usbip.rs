// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::bindings::*;
use crate::binio::{read_struct, write_struct};
use crate::crypto::Token;
use crate::error::R;
use crate::eventloop;
use crate::prompt::Prompt;
use crate::usb;
use std::io::{Error, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::raw::c_char;

const USBIP_VERSION: u16 = 0x0111;

pub fn read_op_common(r: &mut dyn Read) -> Result<(u16, u32, u32), Error> {
    Ok(read_struct::<op_common>(r)?.parse())
}

fn op_common(code: u32) -> op_common {
    op_common {
        version: USBIP_VERSION.to_be(),
        code: u16::try_from(code).unwrap().to_be(),
        status: 0u32.to_be(),
    }
}

fn usb_device() -> usbip_usb_device {
    use std::array::from_fn;
    usbip_usb_device {
        path: from_fn(|i| *b"/frob/bar".get(i).unwrap_or(&0) as c_char),
        busid: from_fn(|i| *b"1-1".get(i).unwrap_or(&0) as c_char),
        busnum: 1u32.to_be(),
        devnum: 1u32.to_be(),
        speed: 2u32.to_be(),
        idVendor: 0,
        idProduct: 0,
        bcdDevice: 0,
        bDeviceClass: 0,
        bDeviceSubClass: 0,
        bDeviceProtocol: 0,
        bConfigurationValue: 0,
        bNumConfigurations: 1,
        bNumInterfaces: 1,
    }
}

fn usb_interface() -> usbip_usb_interface {
    usbip_usb_interface {
        bInterfaceClass: 3u8.to_be(),
        bInterfaceSubClass: 0u8.to_be(),
        bInterfaceProtocol: 0u8.to_be(),
        padding: 0u8.to_be(),
    }
}

pub fn write_op_rep_devlist(stream: &mut dyn Write) -> Result<(), Error> {
    write_struct(stream, &op_common(OP_REP_DEVLIST))?;
    write_struct(stream, &op_devlist_reply { ndev: 1u32.to_be() })?;
    write_struct(stream, &usb_device())?;
    write_struct(stream, &usb_interface())?;
    Ok(())
}

pub fn write_op_rep_import(stream: &mut dyn Write) -> Result<(), Error> {
    write_struct(stream, &op_common(OP_REP_IMPORT))?;
    write_struct(stream, &usb_device())
}

pub fn write_submit_reply(
    stream: &mut dyn Write,
    header: &usbip_header,
    data: &[u8],
    actual_len: Option<i32>,
) -> Result<(), Error> {
    write_struct(
        stream,
        &usbip_header {
            base: usbip_header_basic {
                command: USBIP_RET_SUBMIT.to_be(),
                direction: USBIP_DIR_OUT.to_be(),
                ..header.base
            },
            u: usbip_header__bindgen_ty_1 {
                ret_submit: usbip_header_ret_submit {
                    status: 0,
                    actual_length: actual_len
                        .unwrap_or_else(|| data.len() as i32)
                        .to_be(),
                    start_frame: 0,
                    number_of_packets: 0,
                    error_count: 0,
                },
            },
        },
    )?;
    stream.write(data)?;
    Ok(())
}

pub fn write_submit_reply_error(
    stream: &mut dyn Write,
    header: &usbip_header,
) -> Result<(), Error> {
    write_struct(
        stream,
        &usbip_header {
            base: usbip_header_basic {
                command: USBIP_RET_SUBMIT.to_be(),
                direction: USBIP_DIR_OUT.to_be(),
                ..header.base
            },
            u: usbip_header__bindgen_ty_1 {
                ret_submit: usbip_header_ret_submit {
                    status: 1,
                    actual_length: 0,
                    start_frame: 0,
                    number_of_packets: 0,
                    error_count: 0,
                },
            },
        },
    )
}

pub fn write_unlink_reply(
    stream: &mut dyn Write,
    header: &usbip_header,
    status: i32,
) -> Result<(), Error> {
    write_struct(
        stream,
        &usbip_header {
            base: usbip_header_basic {
                command: USBIP_RET_UNLINK.to_be(),
                direction: USBIP_DIR_OUT.to_be(),
                ..header.base
            },
            u: usbip_header__bindgen_ty_1 {
                ret_unlink: usbip_header_ret_unlink {
                    status: status.to_be(),
                },
            },
        },
    )
}

impl op_common {
    fn parse(&self) -> (u16, u32, u32) {
        (
            u16::from_be(self.version),
            u16::from_be(self.code) as u32,
            u32::from_be(self.status),
        )
    }
}

fn parse_cstring(bytes: &[c_char]) -> R<String> {
    Ok(String::from_utf8(
        bytes
            .iter()
            .take_while(|&&x| x != 0)
            .map(|&x| x as u8)
            .collect(),
    )?)
}

impl op_import_request {
    fn parse(&self) -> String {
        parse_cstring(&self.busid)
            .expect("busid should be a valid UTF-8 sequence")
    }
}

fn read_busid(stream: &mut dyn Read) -> Result<String, Error> {
    Ok(read_struct::<op_import_request>(stream)?.parse())
}

pub fn read_cmd_header(r: &mut dyn Read) -> Result<usbip_header, Error> {
    read_struct(r)
}

pub fn start_server(l: &TcpListener, t: &Token, p: &dyn Prompt) {
    for s in l.incoming() {
        println!("New connection {:?}\n", s);
        handle_stream(&mut s.unwrap(), t, p).unwrap();
    }
}

fn handle_stream(s: &mut TcpStream, t: &Token, p: &dyn Prompt) -> R<()> {
    s.set_nodelay(true)?;
    match read_op_common(s)? {
        (USBIP_VERSION, OP_REQ_DEVLIST, 0) => {
            println!("OP_REQ_DEVLIST");
            write_op_rep_devlist(s)?;
            s.shutdown(std::net::Shutdown::Both)?
        }
        (USBIP_VERSION, OP_REQ_IMPORT, 0) => {
            println!("OP_REQ_IMPORT");
            let busid = read_busid(s)?;
            println!("busid: {}", busid);
            assert!(busid == "1-1");
            write_op_rep_import(s)?;
            println!("import request busid {} complete", busid);
            handle_commands(s, t, p)?
        }
        (version, code, status) => panic!(
            "Unsupported packet: \
	     version: 0x{:x} code: 0x{:x} status: 0x{:x}",
            version, code, status
        ),
    }
    Ok(())
}

fn handle_commands(s: &mut TcpStream, t: &Token, p: &dyn Prompt) -> R<()> {
    let mut dev = usb::Device::new(t, p);
    let mut el = eventloop::EventLoop::new(&mut dev);
    usb::Device::init_callbacks(&mut el);
    el.handle_commands(s)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::binio;
    use crate::crypto::tests::get_token;
    use binio::test::view_as;
    use std::mem::size_of;
    use std::thread::JoinHandle;

    const IMPORT_REQUEST: &[u8] =
        include_bytes!("../poke/usbip-import-request.dat");

    #[test]
    fn parse_import_request() -> R<()> {
        let data = IMPORT_REQUEST;
        const HEADER_SIZE: usize = size_of::<op_common>();
        const REQEUST_SIZE: usize = size_of::<op_import_request>();
        assert_eq!(data.len(), HEADER_SIZE + REQEUST_SIZE);
        assert_eq!(
            view_as::<op_common>(&data[..HEADER_SIZE]).parse(),
            (USBIP_VERSION, OP_REQ_IMPORT, 0)
        );
        let req = view_as::<op_import_request>(&data[HEADER_SIZE..]);
        assert_eq!(req.parse(), "1-1");
        Ok(())
    }

    fn read_usb_device(r: &mut dyn Read) -> R<usbip_usb_device> {
        Ok(read_struct::<usbip_usb_device>(r)?)
    }

    fn test_import_request<T: Read + Write>(s: &mut T) {
        s.write_all(IMPORT_REQUEST).unwrap();
        assert_eq!(
            read_op_common(s).unwrap(),
            (USBIP_VERSION, OP_REP_IMPORT, 0)
        );
        let dev = read_usb_device(s).unwrap();
        assert_eq!(parse_cstring(&dev.path).unwrap(), "/frob/bar");
        assert_eq!(parse_cstring(&dev.busid).unwrap(), "1-1");
    }

    fn start_test_server() -> (TcpStream, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s = TcpStream::connect(addr).unwrap();
        let handle = std::thread::spawn(move || {
            let token = get_token().unwrap();
            let mut s = listener.incoming().next().unwrap().unwrap();
            handle_stream(&mut s, &token, &crate::prompt::Pinentry {})
                .unwrap()
        });
        (s, handle)
    }

    #[test]
    fn test_server() {
        let (mut s, handle) = start_test_server();
        test_import_request(&mut s);
        s.shutdown(std::net::Shutdown::Both).unwrap();
        handle.join().unwrap()
    }
}
