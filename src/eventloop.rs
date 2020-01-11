use crate::usbip;
use usbip::bindings::{usbip_header,
                      USBIP_DIR_IN, USBIP_DIR_OUT,
                      USBIP_CMD_SUBMIT, USBIP_CMD_UNLINK,
                      EINPROGRESS, ENOENT};
use std::convert::TryFrom;
use std::net::TcpStream;
use std::io::Read;

type R<T> = Result<T, Box<dyn std::error::Error>>;

type Dev2HostCallback<T> = fn(&mut EventLoop<T>, &[u8; 8], &mut [u8])
                              -> R<bool>;
type Host2DevCallback<T> = fn(&mut EventLoop<T>, &[u8; 8], &[u8]) -> R<bool>;

pub enum Handler<T> {
    Dev2Host(u8, Dev2HostCallback<T>),
    Host2Dev(u8, Host2DevCallback<T>),
}
    
use Handler::*;

pub struct EventLoop<'a, T> {
    pub state: &'a mut T,
    handlers: Vec<Handler<T>>,

    blocked: Vec<usbip_header>,
    unblocked: Vec<usbip_header>,
}

impl<'a, T> EventLoop<'a, T> {
    pub fn new(state: &'a mut T) -> EventLoop<'a, T> {
        EventLoop {
            state: state,
            handlers: Vec::new(),
            blocked: Vec::new(),
            unblocked: Vec::new()
        }
    }

    pub fn schedule(&mut self, handler: Handler<T>,) -> R<()> {
        self.handlers.push(handler);
        Ok(())
    }

    fn remove_handler(&mut self, endpoint: u8, dev2host: bool,)
                   -> Option<Handler<T>> {
        self.handlers.iter().position(|h| match h {
            Dev2Host(ep, _) => dev2host && *ep == endpoint,
            Host2Dev(ep, _) => !dev2host && *ep == endpoint,
        }).map(|pos| self.handlers.remove(pos))
    }

    pub fn unblock_handler(&mut self, endpoint: u8, dev2host: bool) {
        assert!(self.handlers.iter().any(|h| match h {
            Dev2Host(ep, _) => dev2host && *ep == endpoint,
            Host2Dev(ep, _) => !dev2host && *ep == endpoint,
        }));
        self.blocked.iter().position(
            |h| (u32::from_be(h.base.ep) == (endpoint as u32)
                 && ((u32::from_be(h.base.direction) == USBIP_DIR_IN)
                     == dev2host)))
            .map(|pos| {
                log!("unblock_handler: {}", pos);
                self.unblocked.push(self.blocked.remove(pos));
            });
        ()
    }
                           
    pub fn handle_commands(&mut self, stream: &mut TcpStream,) -> R<()> {
        loop {
            let header = usbip::read_cmd_header(stream)?;
            match u32::from_be(header.base.command) {
                USBIP_CMD_SUBMIT => {
                    log!("CMD_SUBMIT");
                    self.handle_submit(&header, stream)?;
                    while !self.unblocked.is_empty() {
                        log!("processing unblocked");
                        let h = self.unblocked.remove(0);
                        self.handle_submit(&h, stream)?;
                    }
                }
                USBIP_CMD_UNLINK =>
                    self.handle_unlink(&header, stream)?,
                cmd => panic!("Unsupported command: {}", cmd),
            }
        }
    }

    fn handle_submit(
        &mut self,
        header: &usbip_header,
        stream: &mut TcpStream,
    ) -> R<()> {
        let endpoint = u8::try_from(u32::from_be(header.base.ep))?;
        let seqnum = u32::from_be(header.base.seqnum);
        let dev2host = match u32::from_be(header.base.direction) {
            USBIP_DIR_OUT => false,
            USBIP_DIR_IN => true,
            dir => panic!("Invalid direction: {}", dir),
        };
        let cmd = unsafe { header.u.cmd_submit };
        // println!("cmd: {:?}", cmd);
        let transfer_flags = u32::from_be(cmd.transfer_flags);
        let transfer_buffer_length =
            usize::try_from(i32::from_be(cmd.transfer_buffer_length))
                .unwrap();
        log!("handle_submit ep: {} {} seqnum: {} transfer: {}",
             endpoint, if dev2host { "dev->host" } else { "host->dev" },
             seqnum, transfer_buffer_length);
        assert!(transfer_flags & !usbip::URB_DIR_MASK == 0);
        //println!("transfer_buffer_length: {}", transfer_buffer_length);
        let mut v = vec!(0u8; transfer_buffer_length);
        let h = self.remove_handler(endpoint, dev2host);
        match h {
            None => panic!(
                "No handler for endpoint: {} dev2host: {}",
                endpoint, dev2host
            ),
            Some(Dev2Host(ep, f)) => {
                match f(self, &cmd.setup, &mut v[..]) {
                    Err(err) => {
                        println!("Request Error: {} {:?}", err, err);
                        usbip::write_submit_reply_error(stream, header)?;
                        self.handlers.push(Dev2Host(ep, f));
                        //return Err(err)
                        Ok(())
                    },
                    Ok(true) => {
                        usbip::write_submit_reply(stream, header, &v, None)?;
                        self.handlers.push(Dev2Host(ep, f));
                        Ok(())
                    },
                    Ok(false) => {
                        log!("queing request dev->host seqnum: {}",
                             u32::from_be(header.base.seqnum));
                        self.blocked.push(*header);
                        self.handlers.push(Dev2Host(ep, f));
                        Ok(())
                    }
                }
            },
            Some(Host2Dev(ep, f)) => {
                stream.read_exact(&mut v[..])?;
                match self.host2dev_transfer(header, &cmd.setup,
                                             &v[..], f, stream) {
                    Ok(false) => Ok(()),
                    Ok(true) => { self.handlers.push(Host2Dev(ep, f));
                                  Ok(()) },
                    Err(x) => Err(x),
                }
            }
        }
    }

    fn host2dev_transfer(
        &mut self,
        header: &usbip_header,
        setup: &[u8; 8],
        buffer: &[u8],
        f: Host2DevCallback<T>,
        stream: &mut TcpStream,
    ) -> R<bool> {
        match f(self, setup, buffer) {
            Err(err) => {
                panic!("Request Error: {:?}", err);
                //usbip::write_submit_reply_error(stream, header)?
            },
            x => {
                usbip::write_submit_reply(stream, header, &[0u8;0],
                                          Some(buffer.len() as i32))?;
                x
            }
        }
    }

    fn handle_unlink (&mut self, header: &usbip_header,
                      stream: &mut TcpStream) -> R<()> {
        let seqnum = u32::from_be(header.base.seqnum);
        let beseqnum = unsafe{ header.u.cmd_unlink.seqnum };
        let useqnum = u32::from_be(beseqnum);
        log!("CMD_UNLINK: seqnum: {} useqnum {} ", seqnum, useqnum);
        use std::sync::atomic::{AtomicBool, Ordering};
        let mut found = AtomicBool::new(false);
        let f = |h:&usbip_header| -> bool {
            match h.base.seqnum == beseqnum {
                true => { found.store(true, Ordering::Relaxed); false}
                false => true
            }
        };
        self.blocked.retain(f);
        self.unblocked.retain(f);
        let status:i32 = match found.get_mut() {
            true => -(EINPROGRESS as i32),
            false => -(ENOENT as i32),
        };
        usbip::write_unlink_reply(stream, &header, status)?;
        Ok(())
    }
}
