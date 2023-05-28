// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::bindings::*;
use crate::binio::{read_struct, write_struct};
use crate::crypto::Token;
use crate::ctaphid;
use crate::error::{IOR, R};
use crate::usb;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::raw::c_char;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use usb::URB;

struct USBIPServer<'a> {
    device: &'a usb::Device,
    stream: TcpStream,
    // The keys in the active_urbs map are the sequence number of
    // usbip_headers.  The value is usually false, but we set it to to
    // true when the URB has been unlinked.
    active_urbs: Arc<Mutex<BTreeMap<u32, bool>>>,
}

const USBIP_VERSION: u16 = 0x0111;

pub fn read_op_common(r: &mut dyn Read) -> IOR<(u16, u32, u32)> {
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

impl usbip_header {
    fn write_ret_submit(
        &self,
        status: i32,
        buffer: Option<Vec<u8>>,
        stream: &mut dyn Write,
    ) -> IOR<()> {
        let actual_length = match &buffer {
            Some(v) => (v.len() as i32).to_be(),
            None => {
                let cmd = unsafe { self.u.cmd_submit };
                cmd.transfer_buffer_length
            }
        };
        write_struct(
            stream,
            &usbip_header {
                base: usbip_header_basic {
                    command: USBIP_RET_SUBMIT.to_be(),
                    ..self.base
                },
                u: usbip_header__bindgen_ty_1 {
                    ret_submit: usbip_header_ret_submit {
                        status,
                        actual_length,
                        start_frame: 0,
                        number_of_packets: 0,
                        error_count: 0,
                    },
                },
            },
        )?;
        if self.base.is_dev2host() {
            //eprintln!("write: {:x?}", &buffer);
            stream.write(&buffer.unwrap())?;
        }
        Ok(())
    }

    fn write_ret_unlink(&self, status: i32, w: &mut dyn Write) -> IOR<()> {
        write_struct(
            w,
            &usbip_header {
                base: usbip_header_basic {
                    command: USBIP_RET_UNLINK.to_be(),
                    direction: USBIP_DIR_OUT.to_be(),
                    ..self.base
                },
                u: usbip_header__bindgen_ty_1 {
                    ret_unlink: usbip_header_ret_unlink {
                        status: status.to_be(),
                    },
                },
            },
        )
    }
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

fn read_busid(stream: &mut dyn Read) -> IOR<String> {
    Ok(read_struct::<op_import_request>(stream)?.parse())
}

pub fn read_cmd_header(r: &mut dyn Read) -> IOR<Box<usbip_header>> {
    Ok(Box::new(read_struct(r)?))
}

pub fn start_server<'a>(l: &TcpListener, t: Token, p: ctaphid::Prompt) {
    let parser = ctaphid::Parser::new(Arc::new(Mutex::new(t)), p);
    let dev = usb::Device::new(vec![parser.1, parser.0]);
    for s in l.incoming() {
        let tcpstream = s.unwrap();
        log!(USBIP, "TCP: {:?}\n", tcpstream);
        serve(tcpstream, &dev).unwrap();
    }
}

fn serve<'a>(s: TcpStream, dev: &'a usb::Device) -> R<()> {
    s.set_nodelay(true)?;
    let mut server = USBIPServer::<'a> {
        device: dev,
        stream: s,
        active_urbs: Arc::new(Mutex::new(BTreeMap::new())),
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
        //log!("seqnum: {} complete", &header.base.seqnum());
        header
            .write_ret_submit(status, urb.transfer_buffer, &mut out)
            .unwrap();
    }
    log!(USBIP, "completion loop finished");
}

impl<'a> USBIPServer<'a> {
    fn start(&mut self) -> R<()> {
        match read_op_common(&mut self.stream)? {
            (USBIP_VERSION, OP_REQ_DEVLIST, 0) => {
                log!(USBIP, "OP_REQ_DEVLIST");
                self.reply_devlist()?;
                self.stream.shutdown(std::net::Shutdown::Both)?
            }
            (USBIP_VERSION, OP_REQ_IMPORT, 0) => {
                log!(USBIP, "REQ_IMPORT");
                let busid = read_busid(&mut self.stream)?;
                assert!(busid == "1-1");
                self.reply_import()?;
                log!(USBIP, " import request busid {} complete", busid);
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
                        log!(USBIP, "UnexpectedEof");
                        return Ok(());
                    }
                    x => x?,
                };
            match u32::from_be(header.base.command) {
                USBIP_CMD_SUBMIT => {
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
        log!(
            USBIP,
            "handle_submit ep: {} {} seqnum: {} transfer: {}",
            endpoint,
            if dev2host { "dev->host" } else { "host->dev" },
            seqnum,
            transfer_buffer_length
        );
        let transfer_buffer = if dev2host {
            None
        } else {
            let mut buf = vec![0u8; transfer_buffer_length];
            self.stream.read_exact(&mut buf)?;
            Some(buf)
        };
        let active_urbs = self.active_urbs.clone();
        let send = Box::new(move |mut urb: Box<URB>, buf| {
            let seqnum = header.base.seqnum();
            match active_urbs.lock().unwrap().entry(seqnum) {
                Entry::Occupied(e) => {
                    let unlinked = *e.get();
                    e.remove();
                    if unlinked {
                        return Err(usb::CompletionError::Unlinked(buf));
                    }
                }
                Entry::Vacant(_) => panic!("urb not in active_urbs"),
            };
            let old = urb.transfer_buffer;
            urb.transfer_buffer = buf;

            completion_port.send((header, urb, 0)).unwrap();
            Ok(old)
        });
        let urb = Box::new(usb::URB {
            endpoint,
            setup: cmd.setup,
            transfer_buffer,
            transfer_buffer_length,
            complete: Some(send),
        });
        self.active_urbs.lock().unwrap().insert(seqnum, false);
        self.device.submit(urb)
    }

    fn handle_unlink(&mut self, header: Box<usbip_header>) -> IOR<()> {
        let useqnum = u32::from_be(unsafe { header.u.cmd_unlink.seqnum });
        let ep = u32::from_be(header.base.ep);
        let seq = u32::from_be(header.base.seqnum);
        log!(USBIP, "UNLINK: useqnum={} ep={} seq={}", useqnum, ep, seq);
        let status =
            match &mut self.active_urbs.lock().unwrap().entry(useqnum) {
                Entry::Occupied(e) => {
                    e.insert(true);
                    0
                }
                Entry::Vacant(_) => {
                    // TODO: Write a test case for this
                    -(ENOENT as i32)
                }
            };
        header.write_ret_unlink(status, &mut self.stream)
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

    fn make_test_device() -> usb::Device {
        let parser = ctaphid::tests::open_ctaphid();
        usb::Device::new(vec![parser.1, parser.0])
    }

    fn start_test_server() -> (TcpStream, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s = TcpStream::connect(addr).unwrap();
        let dev = make_test_device();
        let handle = std::thread::spawn(move || {
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

    fn test_unlink_request<T: Read + Write>(s: &mut T) {
        test_import_request(s);
        // enque an dev2host request
        {
            let submit = usbip_header {
                base: usbip_header_basic {
                    command: USBIP_CMD_SUBMIT.to_be(),
                    devid: 1u32.to_be(),
                    direction: USBIP_DIR_IN.to_be(),
                    seqnum: 123u32.to_be(),
                    ep: 1u32.to_be(),
                },
                u: usbip_header__bindgen_ty_1 {
                    cmd_submit: usbip_header_cmd_submit {
                        transfer_buffer_length: 64i32.to_be(),
                        transfer_flags: usb::URB_DIR_MASK.to_be(),
                        start_frame: 0,
                        number_of_packets: 0,
                        interval: 0,
                        setup: [0; 8],
                    },
                },
            };
            write_struct(s, &submit).unwrap();
        }
        // unlink it
        {
            let unlink = usbip_header {
                base: usbip_header_basic {
                    command: USBIP_CMD_UNLINK.to_be(),
                    devid: 1u32.to_be(),
                    direction: USBIP_DIR_IN.to_be(),
                    seqnum: 124u32.to_be(),
                    ep: 1u32.to_be(),
                },
                u: usbip_header__bindgen_ty_1 {
                    cmd_unlink: usbip_header_cmd_unlink {
                        seqnum: 123u32.to_be(),
                    },
                },
            };
            write_struct(s, &unlink).unwrap();
            let reply = read_cmd_header(s).unwrap();
            assert_eq!(u32::from_be(reply.base.command), USBIP_RET_UNLINK);
            assert_eq!(
                i32::from_be(unsafe { reply.u.ret_unlink.status }),
                0
            );
        }
        // unlink an unknown sequence number
        {
            let unlink2 = usbip_header {
                base: usbip_header_basic {
                    command: USBIP_CMD_UNLINK.to_be(),
                    devid: 1u32.to_be(),
                    direction: USBIP_DIR_IN.to_be(),
                    seqnum: 125u32.to_be(),
                    ep: 1u32.to_be(),
                },
                u: usbip_header__bindgen_ty_1 {
                    cmd_unlink: usbip_header_cmd_unlink {
                        seqnum: 122u32.to_be(),
                    },
                },
            };
            write_struct(s, &unlink2).unwrap();
            let reply2 = read_cmd_header(s).unwrap();
            assert_eq!(
                u32::from_be(reply2.base.command),
                USBIP_RET_UNLINK
            );
            assert_eq!(
                i32::from_be(unsafe { reply2.u.ret_unlink.status }),
                -(ENOENT as i32)
            );
        }
    }

    #[test]
    fn test_unlink() {
        let (mut s, handle) = start_test_server();
        test_unlink_request(&mut s);
        s.shutdown(std::net::Shutdown::Both).unwrap();
        handle.join().unwrap()
    }
}
