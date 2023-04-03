// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::bindings::{
    usbip_header, usbip_header_basic, EINPROGRESS, ENOENT,
    USBIP_CMD_SUBMIT, USBIP_CMD_UNLINK, USBIP_DIR_IN, USBIP_DIR_OUT,
};
use crate::error::R;
use crate::usb;
use crate::usbip;
use packed_struct::PackedStruct;
use std::convert::TryFrom;
use std::io::{ErrorKind, Read};
use std::net::TcpStream;
use usb::URB;

type Dev2HostCallback<T> = fn(&mut EventLoop<T>, Box<URB<usbip_header>>);
type Host2DevCallback<T> = fn(&mut EventLoop<T>, Box<URB<usbip_header>>);

pub enum Handler<T> {
    Dev2Host(u8, Dev2HostCallback<T>),
    Host2Dev(u8, Host2DevCallback<T>),
}

use Handler::*;

pub struct EventLoop<'a, T> {
    pub state: &'a mut T,
    handlers: Vec<Handler<T>>,

    blocked: Vec<Box<usbip_header>>,
    unblocked: Vec<Box<usbip_header>>,
}

impl<'a, T> EventLoop<'a, T> {
    pub fn new(state: &'a mut T) -> EventLoop<'a, T> {
        EventLoop {
            state: state,
            handlers: Vec::new(),
            blocked: Vec::new(),
            unblocked: Vec::new(),
        }
    }

    pub fn schedule(&mut self, handler: Handler<T>) {
        self.handlers.push(handler);
    }

    fn remove_handler(&mut self, ep: u8, d2h: bool) -> Option<Handler<T>> {
        self.handlers
            .iter()
            .position(|h| match h {
                &Dev2Host(endpoint, _) => d2h && endpoint == ep,
                &Host2Dev(endpoint, _) => !d2h && endpoint == ep,
            })
            .map(|pos| self.handlers.remove(pos))
    }

    pub fn unblock_handler(&mut self, endpoint: u8, dev2host: bool) {
        assert!(self.handlers.iter().any(|h| match h {
            Dev2Host(ep, _) => dev2host && *ep == endpoint,
            Host2Dev(ep, _) => !dev2host && *ep == endpoint,
        }));
        self.blocked
            .iter()
            .position(|h| {
                (h.base.ep() == endpoint)
                    && (h.base.direction() == dev2host)
            })
            .map(|pos| {
                log!("unblock_handler: {}", pos);
                self.unblocked.push(self.blocked.remove(pos));
            });
        ()
    }

    pub fn handle_commands(&mut self, stream: &mut TcpStream) -> R<()> {
        loop {
            let header: Box<usbip_header> =
                match usbip::read_cmd_header(stream) {
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                        return Ok(())
                    }
                    x => x?,
                };
            match u32::from_be(header.base.command) {
                USBIP_CMD_SUBMIT => {
                    log!("CMD_SUBMIT");
                    self.handle_submit(header, stream)?;
                    while !self.unblocked.is_empty() {
                        log!("processing unblocked");
                        let h = self.unblocked.remove(0);
                        self.handle_submit(h, stream)?;
                    }
                }
                USBIP_CMD_UNLINK => self.handle_unlink(&header, stream)?,
                cmd => panic!("Unsupported command: {}", cmd),
            }
        }
    }

    fn handle_submit(
        &mut self,
        header: Box<usbip_header>,
        stream: &mut TcpStream,
    ) -> R<()> {
        let endpoint = header.base.ep();
        let seqnum = header.base.seqnum();
        let dev2host = header.base.direction();
        let cmd = unsafe { header.u.cmd_submit };
        let transfer_flags = u32::from_be(cmd.transfer_flags);
        let transfer_buffer_length =
            usize::try_from(i32::from_be(cmd.transfer_buffer_length))
                .unwrap();
        log!(
            "handle_submit ep: {} {} seqnum: {} transfer: {}",
            endpoint,
            if dev2host { "dev->host" } else { "host->dev" },
            seqnum,
            transfer_buffer_length
        );
        assert!(transfer_flags & !usb::URB_DIR_MASK == 0);
        //println!("transfer_buffer_length: {}", transfer_buffer_length);
        let mut v = vec![0u8; transfer_buffer_length];
        let h =
            self.remove_handler(endpoint, dev2host).unwrap_or_else(|| {
                panic!(
                    "No handler for endpoint: {} dev2host: {}",
                    endpoint, dev2host
                )
            });
        match h {
            Dev2Host(_ep, f) => {
                let setup = usb::SetupPacket::unpack(&cmd.setup).unwrap();
                let (tx, rx) = std::sync::mpsc::channel();
                let reply = Box::new(move |urb| tx.send(urb).unwrap());
                let urb = Box::new(usb::URB {
                    setup,
                    transfer_buffer: v,
                    endpoint,
                    complete: Some(reply),
                    context: header,
                    status: None,
                });
                f(self, urb);
                let urb = rx.recv()?;
                match urb.status.unwrap() {
                    Err(err) => {
                        println!("Request Error: {} {:?}", err, err);
                        usbip::write_submit_reply_error(
                            stream,
                            &urb.context,
                        )?;
                        self.schedule(h);
                        //return Err(err)
                        Ok(())
                    }
                    Ok(true) => {
                        usbip::write_submit_reply(
                            stream,
                            &urb.context,
                            &urb.transfer_buffer,
                            None,
                        )?;
                        self.schedule(h);
                        Ok(())
                    }
                    Ok(false) => {
                        log!(
                            "queing request dev->host seqnum: {}",
                            urb.context.base.seqnum()
                        );
                        self.blocked.push(urb.context);
                        self.schedule(h);
                        Ok(())
                    }
                }
            }
            Host2Dev(_ep, f) => {
                stream.read_exact(&mut v[..])?;
                self.host2dev_transfer(
                    endpoint, header, &cmd.setup, v, f, stream,
                )
                .map(|flag| match flag {
                    true => self.schedule(h),
                    false => (),
                })
            }
        }
    }

    fn host2dev_transfer(
        &mut self,
        endpoint: u8,
        header: Box<usbip_header>,
        setup: &[u8; 8],
        buffer: Vec<u8>,
        f: Host2DevCallback<T>,
        stream: &mut TcpStream,
    ) -> R<bool> {
        let setup = usb::SetupPacket::unpack(&setup).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reply = Box::new(move |urb| tx.send(urb).unwrap());
        let urb = Box::new(usb::URB {
            setup,
            transfer_buffer: buffer,
            endpoint,
            complete: Some(reply),
            context: header,
            status: None,
        });
        f(self, urb);
        let urb = rx.recv()?;
        match urb.status.unwrap() {
            Err(err) => {
                panic!("Request Error: {:?}", err);
                //usbip::write_submit_reply_error(stream, header)?
            }
            x => {
                usbip::write_submit_reply(
                    stream,
                    &urb.context,
                    &[0u8; 0],
                    Some(urb.transfer_buffer.len() as i32),
                )?;
                x
            }
        }
    }

    fn handle_unlink(
        &mut self,
        header: &usbip_header,
        stream: &mut TcpStream,
    ) -> R<()> {
        let useqnum = u32::from_be(unsafe { header.u.cmd_unlink.seqnum });
        log!("CMD_UNLINK: useqnum {} ", useqnum);
        let f = |h: &Box<usbip_header>| h.base.seqnum() == useqnum;
        let nf = |h: &Box<usbip_header>| !f(h);
        let found =
            self.blocked.iter().any(f) || self.unblocked.iter().any(f);
        self.blocked.retain(nf);
        self.unblocked.retain(nf);
        let status: i32 = match found {
            true => -(EINPROGRESS as i32),
            false => -(ENOENT as i32),
        };
        usbip::write_unlink_reply(stream, &header, status)?;
        Ok(())
    }
}

// Some accessors. Mostly to do the big-endian conversion.
impl usbip_header_basic {
    fn ep(&self) -> u8 {
        match u32::from_be(self.ep) {
            ep @ 0..=15 => ep as u8,
            ep => panic!("Invalid endpoint: {}", ep),
        }
    }
    fn direction(&self) -> bool {
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
