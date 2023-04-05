// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::bindings::*;
use crate::binio::{read_struct, write_struct};
use crate::crypto::Token;
use crate::ctaphid;
use crate::error::{IOR, R};
use crate::prompt::Prompt;
use crate::usb;
use packed_struct::PackedStruct;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::raw::c_char;
use std::sync::mpsc::{Receiver, Sender};
use usb::URB;

struct USBIPServer<'a> {
    device: &'a usb::Device,
    stream: TcpStream,
}

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

fn usb_device(dev: &usb::Device) -> usbip_usb_device {
    use std::array::from_fn;
    let d = &dev.device_descriptor;
    let c = &dev.config_descriptor;
    usbip_usb_device {
        path: from_fn(|i| *b"/frob/bar".get(i).unwrap_or(&0) as c_char),
        busid: from_fn(|i| *b"1-1".get(i).unwrap_or(&0) as c_char),
        busnum: 1u32.to_be(),
        devnum: 1u32.to_be(),
        speed: 2u32.to_be(),
        idVendor: d.idVendor,
        idProduct: d.idProduct,
        bcdDevice: d.bcdDevice,
        bDeviceClass: d.bDeviceClass,
        bDeviceSubClass: d.bDeviceSubClass,
        bDeviceProtocol: d.bDeviceProtocol,
        bConfigurationValue: c.bConfigurationValue,
        bNumConfigurations: d.bNumConfigurations,
        bNumInterfaces: c.bNumInterfaces,
    }
}

fn usb_interface(dev: &usb::Device) -> usbip_usb_interface {
    let i = &dev.interface_descriptor;
    usbip_usb_interface {
        bInterfaceClass: i.bInterfaceClass,
        bInterfaceSubClass: i.bInterfaceSubClass,
        bInterfaceProtocol: i.bInterfaceProtocol,
        padding: 0u8.to_be(),
    }
}

fn write_submit_reply(
    stream: &mut dyn Write,
    header: &usbip_header,
    data: &[u8],
) -> IOR<()> {
    write_struct(
        stream,
        &usbip_header {
            base: usbip_header_basic {
                command: USBIP_RET_SUBMIT.to_be(),
                //direction: USBIP_DIR_OUT.to_be(),
                ..header.base
            },
            u: usbip_header__bindgen_ty_1 {
                ret_submit: usbip_header_ret_submit {
                    status: 0,
                    actual_length: (data.len() as i32).to_be(),
                    start_frame: 0,
                    number_of_packets: 0,
                    error_count: 0,
                },
            },
        },
    )?;
    if header.base.is_dev2host() {
        stream.write(data)?;
    }
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

pub fn read_cmd_header(r: &mut dyn Read) -> IOR<Box<usbip_header>> {
    Ok(Box::new(read_struct(r)?))
}

pub fn start_server<'a>(l: &TcpListener, t: Token, p: Box<dyn Prompt>) {
    let parser = ctaphid::Parser::new(t, p);
    let dev = usb::Device::new(vec![parser.1, parser.0]);
    for s in l.incoming() {
        println!("New connection {:?}\n", s);
        serve(s.unwrap(), &dev).unwrap();
    }
}

fn serve<'a>(s: TcpStream, dev: &'a usb::Device) -> R<()> {
    s.set_nodelay(true)?;
    let mut server = USBIPServer::<'a> {
        device: dev,
        stream: s,
    };
    server.start()
}

// Some accessors. Mostly to do the big-endian conversion.
impl usbip_header_basic {
    fn ep(&self) -> u8 {
        match u32::from_be(self.ep) {
            ep @ 0..=15 => ep as u8,
            ep => panic!("Invalid endpoint: {}", ep),
        }
    }
    fn is_dev2host(&self) -> bool {
        match u32::from_be(self.direction) {
            USBIP_DIR_OUT => false,
            USBIP_DIR_IN => true,
            dir => panic!("Invalid direction: {}", dir),
        }
    }
    fn seqnum(&self) -> u32 {
        u32::from_be(self.seqnum)
    }
}

type CompletionArgs = (Box<usbip_header>, Box<URB>, i32);

fn completion_loop(rx: Receiver<CompletionArgs>, mut out: TcpStream) {
    for (header, urb, status) in rx {
        log!("complete: {:?}", &header.base.seqnum());
        match status {
            0 => {
                write_submit_reply(
                    &mut out,
                    &header,
                    &urb.transfer_buffer,
                )
                .unwrap();
            }
            err => {
                println!("Request Error: {} {:?}", err, err);
                write_submit_reply_error(&mut out, &header).unwrap();
            }
        }
    }
}

impl<'a> USBIPServer<'a> {
    fn start(&mut self) -> R<()> {
        match read_op_common(&mut self.stream)? {
            (USBIP_VERSION, OP_REQ_DEVLIST, 0) => {
                println!("OP_REQ_DEVLIST");
                self.reply_devlist()?;
                self.stream.shutdown(std::net::Shutdown::Both)?
            }
            (USBIP_VERSION, OP_REQ_IMPORT, 0) => {
                println!("OP_REQ_IMPORT");
                let busid = read_busid(&mut self.stream)?;
                println!("busid: {}", busid);
                assert!(busid == "1-1");
                self.reply_import()?;
                println!("import request busid {} complete", busid);
                self.handle_commands()?
            }
            (version, code, status) => panic!(
                "Unsupported packet: \
		 version: 0x{:x} code: 0x{:x} status: 0x{:x}",
                version, code, status
            ),
        }
        Ok(())
    }

    fn reply_import(&mut self) -> IOR<()> {
        let out = &mut self.stream;
        write_struct(out, &op_common(OP_REP_IMPORT))?;
        write_struct(out, &usb_device(&self.device))
    }

    fn reply_devlist(&mut self) -> IOR<()> {
        let out = &mut self.stream;
        write_struct(out, &op_common(OP_REP_DEVLIST))?;
        write_struct(out, &op_devlist_reply { ndev: 1u32.to_be() })?;
        write_struct(out, &usb_device(&self.device))?;
        write_struct(out, &usb_interface(&self.device))
    }

    fn handle_commands(&mut self) -> R<()> {
        let (completion_port, rx) = std::sync::mpsc::channel();
        let output = self.stream.try_clone()?;
        std::thread::spawn(move || completion_loop(rx, output));
        loop {
            let header: Box<usbip_header> =
                match read_cmd_header(&mut self.stream) {
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                        return Ok(())
                    }
                    x => x?,
                };
            match u32::from_be(header.base.command) {
                USBIP_CMD_SUBMIT => {
                    log!("CMD_SUBMIT");
                    self.handle_submit(header, completion_port.clone())?;
                }
                USBIP_CMD_UNLINK => self.handle_unlink(header)?,
                cmd => panic!("Unsupported command: {}", cmd),
            }
        }
    }

    fn handle_submit(
        &mut self,
        header: Box<usbip_header>,
        completion_port: Sender<CompletionArgs>,
    ) -> R<()> {
        let endpoint = header.base.ep();
        let seqnum = header.base.seqnum();
        let dev2host = header.base.is_dev2host();
        let cmd = unsafe { header.u.cmd_submit };
        let transfer_flags = u32::from_be(cmd.transfer_flags);
        let transfer_buffer_length =
            i32::from_be(cmd.transfer_buffer_length) as usize;
        assert!(transfer_flags & !usb::URB_DIR_MASK == 0);
        //println!("transfer_buffer_length: {}", transfer_buffer_length);
        let mut transfer_buffer = vec![0u8; transfer_buffer_length];
        let setup = usb::SetupPacket::unpack(&cmd.setup).unwrap();
        log!(
            "handle_submit ep: {} {} seqnum: {} transfer: {} setup={:?}",
            endpoint,
            if dev2host { "dev->host" } else { "host->dev" },
            seqnum,
            transfer_buffer_length,
            &cmd.setup
        );
        if !dev2host {
            self.stream.read_exact(&mut transfer_buffer)?
        }
        let snd = Box::new(move |urb, status| {
            completion_port.send((header, urb, status)).unwrap()
        });
        let urb = Box::new(usb::URB {
            setup,
            transfer_buffer,
            endpoint,
            complete: Some(snd),
            status: None,
        });
        self.device.submit(urb)
    }

    fn handle_unlink(&mut self, header: Box<usbip_header>) -> R<()> {
        let useqnum = u32::from_be(unsafe { header.u.cmd_unlink.seqnum });
        log!("CMD_UNLINK: useqnum {} ", useqnum);
        //todo!();
        // let status: i32 = match found {
        //     true => -(EINPROGRESS as i32),
        //     false => -(ENOENT as i32),
        // };
        let status = -(ENOENT as i32);
        write_unlink_reply(&mut self.stream, &header, status)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::binio;
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
            let dev = usb::Device::new(vec![]);
            let s = listener.incoming().next().unwrap().unwrap();
            serve(s, &dev).unwrap()
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
