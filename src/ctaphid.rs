// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::crypto::Token;
use crate::ctap2;
use crate::u2f;
use crate::usb;
use packed_struct::prelude::PackedStruct;
use std::cmp::min;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, RecvError, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};
use usb::URB;

pub type Prompt = fn(&str) -> Result<bool, String>;
type QPort = Sender<Pkt>;

pub struct Parser {
    input_rx: Receiver<ParserInput>,
    input_tx: Sender<ParserInput>,
    queue_port: QPort,
    token: Token,
    prompt: Prompt,
    cid_counter: u32,
    tag_counter: Tag,
}

type Tag = usize;

#[derive(Debug)]
enum ParserInput {
    Asm(AR),
    Status(TransactionStatus),
    Consent(bool, Tag),
}

#[derive(Debug)]
enum TransactionStatus {
    Done(Vec<u8>),
    ConsentNeeded(String, Sender<Result<bool, ()>>),
}

struct TPort(Sender<ParserInput>);
impl TPort {
    // The error result indicates a CTAPHID_CANCEL
    fn get_consent(&self, s: String) -> Result<bool, ()> {
        let (tx, rx) = mpsc::channel();
        self.send(TransactionStatus::ConsentNeeded(s, tx));
        rx.recv().unwrap_or(Ok(false))
    }
    fn done(&self, response: Vec<u8>) {
        self.send(TransactionStatus::Done(response))
    }
    fn send(&self, msg: TransactionStatus) {
        self.0.send(ParserInput::Status(msg)).unwrap();
    }
}

const PACKET_SIZE: usize = 64;
const INIT_SIZE: usize = PACKET_SIZE - 7;
const CONT_SIZE: usize = PACKET_SIZE - 5;

const CTAPHID_BROADCAST_CID: u32 = 0xFFFFFFFF;

const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_PING: u8 = 0x01;
const CTAPHID_CANCEL: u8 = 0x11;
const CTAPHID_CBOR: u8 = 0x10;
const CTAPHID_MSG: u8 = 0x03;
const CTAPHID_ERROR: u8 = 0x3F;
const CTAPHID_KEEPALIVE: u8 = 0x3B;
//const CTAPHID_VENDOR_FIRST: u8 = 0x40;

//const CAPABILITY_WINK: u8 = 0x01;
const CAPABILITY_CBOR: u8 = 0x04;
//const CAPABILITY_NMSG: u8 = 0x08;

const STATUS_PROCESSING: u8 = 1;
const STATUS_UPNEEDED: u8 = 2;

//const ERR_INVALID_CMD: u8 = 0x01;
//const ERR_INVALID_PAR: u8 = 0x02;
const ERR_BUSY: u8 = 0x06;
#[allow(dead_code)]
const ERR_INVALID_CHANNEL: u8 = 0x0B;
//const ERR_INVALID_OPTION: u8 = 0x2C;

const PROTOCOL_VERSION: u8 = 2;

#[derive(PackedStruct, Debug)]
#[packed_struct(endian = "msb")]
pub struct InitResponse {
    nonce: [u8; 8],
    channelid: u32,
    protocol_version: u8,
    device_major_version: u8,
    device_minor_version: u8,
    device_build_version: u8,
    capabilities: u8,
}

fn output_loop(output: Receiver<Box<URB>>, queue: Receiver<Pkt>) {
    log!("start output loop");
    for pkt in queue {
        let mut buf = Some(pkt.into());
        loop {
            let urb = output.recv().unwrap();
            log!("output urb");
            match urb.complete(buf) {
                Ok(None) => break,
                Ok(_) => panic!("complete() returned a buffer"),
                Err(usb::CompletionError::Unlinked(b)) => {
                    log!("skipping unlinked urb");
                    buf = b;
                    continue;
                }
            }
        }
    }
    log!("output loop finished");
}

type Pkt = [u8; PACKET_SIZE];
struct InitializationPacket<'a>(&'a Pkt);
struct ContinuationPacket<'a>(&'a Pkt);

impl<'a> InitializationPacket<'a> {
    fn write(pkt: &mut Pkt, cid: u32, cmd: u8, bcnt: u16, data: &[u8]) {
        pkt[0..4].copy_from_slice(cid.to_be_bytes().as_slice());
        pkt[4] = cmd | (1 << 7);
        pkt[5..7].copy_from_slice(bcnt.to_be_bytes().as_slice());
        pkt[7..7 + data.len()].copy_from_slice(data);
    }
    fn cid(&self) -> u32 {
        u32::from_be_bytes(self.0[..4].try_into().unwrap())
    }
    fn cmd(&self) -> (bool, u8) {
        let cmdbyte = self.0[4];
        // in continuation packets, the highest bit is cleared
        let is_cont = (cmdbyte >> 7) == 0;
        let cmd = cmdbyte & !(1 << 7);
        (is_cont, cmd)
    }
    fn data(&self) -> (usize, &[u8]) {
        let bcnt = u16::from_be_bytes([self.0[5], self.0[6]]) as usize;
        (bcnt, &self.0[7..min(7 + bcnt, PACKET_SIZE)])
    }
}

impl<'a> ContinuationPacket<'a> {
    fn write(pkt: &mut Pkt, cid: u32, seq: u8, data: &[u8]) {
        pkt[0..4].copy_from_slice(cid.to_be_bytes().as_slice());
        pkt[4] = seq;
        pkt[5..5 + data.len()].copy_from_slice(data);
    }
    fn cid(&self) -> u32 {
        InitializationPacket(&self.0).cid()
    }
    fn seq(&self) -> (bool, u8) {
        InitializationPacket(&self.0).cmd()
    }
    fn data(&self, bcnt: usize) -> &[u8] {
        &self.0[5..min(5 + bcnt, PACKET_SIZE)]
    }
}

impl From<Box<URB>> for Pkt {
    fn from(urb: Box<URB>) -> Self {
        match urb.complete(None) {
            Ok(Some(buffer)) => buffer[..].try_into().unwrap(),
            Ok(None) => panic!("no transfer buffer in input urb"),
            Err(_) => todo!(),
        }
    }
}

#[derive(Debug)]
struct Message {
    cid: u32,
    cmd: u8,
    data: Vec<u8>,
}

impl Message {
    fn new(cid: u32, cmd: u8, data: Vec<u8>) -> Message {
        Message { cid, cmd, data }
    }
    fn packetize(self) -> Packetizer {
        Packetizer { msg: self, seq: 0 }
    }
}

struct Packetizer {
    msg: Message,
    seq: usize,
}

impl Iterator for Packetizer {
    type Item = Pkt;
    fn next(&mut self) -> Option<Self::Item> {
        let (seq, msg) = (self.seq, &self.msg);
        let (data, len) = (&msg.data, msg.data.len());
        match seq {
            0 => {
                let mut pkt = [0u8; PACKET_SIZE];
                let bcnt = u16::try_from(len).unwrap();
                let data = &data[..min(INIT_SIZE, len)];
                let w = InitializationPacket::write;
                w(&mut pkt, msg.cid, msg.cmd, bcnt, data);
                self.seq = 1;
                Some(pkt)
            }
            _ => match INIT_SIZE + CONT_SIZE * (seq - 1) {
                pos if len <= pos => None,
                pos => {
                    self.seq = seq + 1;
                    let mut pkt = [0u8; PACKET_SIZE];
                    let data = &data[pos..min(pos + PACKET_SIZE - 5, len)];
                    let w = ContinuationPacket::write;
                    assert!(seq <= 0x80);
                    w(&mut pkt, msg.cid, (seq - 1) as u8, data);
                    Some(pkt)
                }
            },
        }
    }
}

struct Assembler {
    input: Box<dyn Iterator<Item = Pkt>>,
    state: Option<Box<dyn FnOnce(&mut Assembler) -> Option<AR>>>,
}

type AR = Result<Message, AssemblerError>;

#[derive(Debug)]
enum AssemblerError {
    //SpuriousContinuationPacket,
    //InvalidSeq(u32),
    ChannelBusy(u32),
    //Timeout(u32),
    EndOfInput,
}

impl Assembler {
    fn new(input: Box<dyn Iterator<Item = Pkt>>) -> Self {
        Self { input, state: None }
    }
    fn assemble(&mut self) -> Option<AR> {
        match self.input.next() {
            Some(pkt) => self.assemble_init(pkt),
            _ => return None,
        }
    }
    fn assemble_init(&mut self, pkt: Pkt) -> Option<AR> {
        let p = InitializationPacket(&pkt);
        let cid = p.cid();
        let cmd = match p.cmd() {
            (false, cmd) => cmd,
            (true, _) => {
                // ignore spurious continuation packet
                eprintln!("ignoring spurious continuation packet");
                return self.assemble();
            }
        };
        let (bcnt, data) = p.data();
        let msg = Message::new(cid, cmd, data.to_vec());
        if bcnt == msg.data.len() {
            return Some(Ok(msg));
        }
        let deadline = Instant::now() + Duration::from_millis(50);
        self.assemble_cont(bcnt - INIT_SIZE, 0, msg, deadline)
    }
    fn assemble_cont(
        &mut self,
        mut bcnt: usize,
        mut seq: u8,
        mut msg: Message,
        deadline: Instant,
    ) -> Option<AR> {
        loop {
            let pkt: Pkt = self.input.next().unwrap();
            if Instant::now() > deadline {
                self.state = Some(Box::new(move |s| s.assemble_init(pkt)));
                todo!() //ERR_MSG_TIMEOUT
            }
            let p = ContinuationPacket(&pkt);
            if p.cid() != msg.cid {
                self.state = Some(Box::new(move |s| {
                    s.assemble_cont(bcnt, seq, msg, deadline)
                }));
                return Some(Err(AssemblerError::ChannelBusy(p.cid())));
            }
            match p.seq() {
                (false, _) => todo!(), //ERR_INVALID_SEQ; Handle CANCEL?
                (true, pseq) if pseq != seq => todo!(), //ERR_INVALID_SEQ
                _ => (),
            }
            msg.data.extend_from_slice(p.data(bcnt));
            if bcnt <= CONT_SIZE {
                return Some(Ok(msg));
            }
            seq += 1;
            bcnt -= CONT_SIZE;
        }
    }
}

struct URBReceiver(Receiver<Box<URB>>);
impl Iterator for URBReceiver {
    type Item = Pkt;
    fn next(&mut self) -> Option<Self::Item> {
        match self.0.recv() {
            Ok(urb) => Some(Pkt::from(urb)),
            Err(RecvError) => None,
        }
    }
}

impl Iterator for Assembler {
    type Item = AR;
    fn next(&mut self) -> Option<Self::Item> {
        match self.state.take() {
            None => self.assemble(),
            Some(f) => f(self),
        }
    }
}

impl Parser {
    pub fn new(
        token: Token,
        prompt: Prompt,
    ) -> (Sender<Box<URB>>, Sender<Box<URB>>) {
        let (input, asm_rx) = mpsc::channel();
        let (parser_tx, parser_rx) = mpsc::channel();
        let (queue_tx, queue_rx) = mpsc::channel();
        let (output, output_rx) = mpsc::channel();
        let parser_tx2 = parser_tx.clone();
        thread::spawn(move || {
            let assembler = Assembler::new(Box::new(URBReceiver(asm_rx)));
            use ParserInput::Asm;
            for r in assembler {
                if parser_tx2.send(Asm(r)).is_err() {
                    return ();
                }
            }
            parser_tx2.send(Asm(Err(AssemblerError::EndOfInput))).ok();
        });
        thread::spawn(move || {
            let mut s = Self {
                input_rx: parser_rx,
                input_tx: parser_tx,
                queue_port: queue_tx,
                token,
                prompt: prompt,
                cid_counter: 0,
                tag_counter: 0,
            };
            s.input_loop()
        });
        thread::spawn(move || output_loop(output_rx, queue_rx));
        (input, output)
    }
    fn input_loop(&mut self) {
        log!("start input loop");
        loop {
            use AssemblerError::*;
            use ParserInput::*;
            match self.input_rx.recv() {
                Ok(Asm(Ok(msg))) => self.dispatch_message(msg),
                Err(RecvError) => break,
                Ok(Asm(Err(ChannelBusy(cid)))) => {
                    self.send_error(cid, ERR_BUSY)
                }
                Ok(c @ Consent(..)) => {
                    log!("ignoring belated consent: {:?}", c)
                }
                Ok(Status(..)) => todo!(), //ignore canceled transcations
                Ok(x) => {
                    dbg!(x);
                    todo!()
                }
            }
        }
        log!("input loop finished");
    }
    fn dispatch_message(&mut self, msg: Message) {
        let Message { cid, cmd, data } = msg;
        if !self.is_valid_channel_id(cid, cmd) {
            dbg!(cid);
            todo!()
        }
        match cmd {
            CTAPHID_INIT => match (cid, data.len()) {
                (CTAPHID_BROADCAST_CID, 8) => {
                    self.allocate_channel(&data.try_into().unwrap())
                }
                (_, 8) => todo!(),
                _ => todo!(),
            },
            CTAPHID_PING => self.ping_cmd(cid, data),
            CTAPHID_CBOR => self.cbor_cmd(cid, data),
            CTAPHID_MSG => self.msg_cmd(cid, data),
            CTAPHID_CANCEL => (),
            _ => todo!(),
        }
    }
    fn is_valid_channel_id(&self, cid: u32, cmd: u8) -> bool {
        match (cid, cmd) {
            (CTAPHID_BROADCAST_CID, CTAPHID_INIT) => true,
            (0, _) => false,
            _ => cid <= self.cid_counter,
        }
    }
    fn allocate_channel(&mut self, nonce: &[u8; 8]) {
        let cid = self.cid_counter + 1;
        self.cid_counter = cid;
        log!("allocate channel: {}", cid);
        let response = InitResponse {
            nonce: nonce.clone(),
            channelid: cid,
            protocol_version: PROTOCOL_VERSION,
            device_major_version: 0,
            device_minor_version: 0,
            device_build_version: 0,
            capabilities: CAPABILITY_CBOR,
        }
        .pack()
        .unwrap()
        .to_vec();
        self.send_reply(CTAPHID_BROADCAST_CID, CTAPHID_INIT, response)
    }
    fn send_reply(&self, cid: u32, cmd: u8, data: Vec<u8>) {
        let queue = &self.queue_port;
        let msg = Message::new(cid, cmd, data);
        log!("msg={:0X?}", msg);
        for pkt in msg.packetize() {
            queue.send(pkt).unwrap();
        }
    }
    fn send_error(&self, cid: u32, code: u8) {
        eprintln!("send_error");
        self.send_reply(cid, CTAPHID_ERROR, vec![code])
    }
    fn ping_cmd(&mut self, cid: u32, data: Vec<u8>) {
        self.send_reply(cid, CTAPHID_PING, data)
    }
    fn monitor_request(
        &mut self,
        cid: u32,
        cmd: u8,
        data: Vec<u8>,
        fun: fn(Vec<u8>, ctap2::GetConsent, Token) -> Vec<u8>,
    ) {
        eprintln!("monitor_request");
        let token = self.token.clone();
        let tx = self.input_tx.clone();
        let tag = self.tag_counter;
        self.tag_counter = tag + 1;
        let handle = thread::spawn(move || {
            let tport = TPort(tx);
            let get_consent = |x| tport.get_consent(x);
            tport.done(fun(data, &get_consent, token))
        });
        type Status = Option<Sender<Result<bool, ()>>>;
        let mut status = None;
        let change_status = |s: &mut Status, new: Status| {
            if cmd == CTAPHID_CBOR {
                let code = match s {
                    None => STATUS_PROCESSING,
                    Some(_) => STATUS_UPNEEDED,
                };
                log!("sending CTAPHID_KEEPALIVE");
                self.send_reply(cid, CTAPHID_KEEPALIVE, vec![code]);
            }
            *s = new;
        };
        loop {
            use ParserInput::*;
            use TransactionStatus::*;
            match self.input_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Status(Done(response))) => {
                    assert!(status.is_none());
                    handle.join().unwrap();
                    break self.send_reply(cid, cmd, response);
                }
                Ok(Status(ConsentNeeded(prompt, tx))) => {
                    assert!(status.is_none());
                    change_status(&mut status, Some(tx));
                    self.yes_or_no_p(prompt, tag)
                }
                Ok(Consent(answer, t)) => match &status {
                    _ if t != tag => {
                        log!("ignoring belated consent");
                        todo!()
                    }
                    Some(tx) if t == tag => {
                        tx.send(Ok(answer)).unwrap();
                        change_status(&mut status, None);
                    }
                    _ => todo!(),
                },
                Err(RecvTimeoutError::Timeout) => {
                    eprintln!("timeout");
                    let s = status.clone();
                    change_status(&mut status, s);
                }
                Ok(Asm(Ok(msg))) => match (msg.cmd, &status) {
                    _ if msg.cid != cid => {
                        log!("busy tag={} cid={}", tag, cid);
                        self.send_error(msg.cid, ERR_BUSY)
                    }
                    (CTAPHID_CANCEL, Some(tx)) => {
                        log!("cancelling tag={} cid={}", tag, cid);
                        tx.send(Err(())).unwrap();
                        change_status(&mut status, None);
                    }
                    (CTAPHID_CANCEL, None) => {
                        log!("can't cancel while processing");
                    }
                    _ => todo!(),
                },
                msg => {
                    dbg!(Some(msg));
                    todo!()
                }
            }
        }
    }
    fn yes_or_no_p(&self, query: String, tag: Tag) {
        let prompt = self.prompt.clone();
        let tx = self.input_tx.clone();
        thread::spawn(move || {
            let r = prompt(&query);
            match r {
                Ok(x) => tx.send(ParserInput::Consent(x, tag)).unwrap(),
                Err(e) => {
                    log!("yes_or_no_p failed: {:?}", e);
                    tx.send(ParserInput::Consent(false, tag)).unwrap()
                }
            }
        });
    }
    fn cbor_cmd(&mut self, cid: u32, data: Vec<u8>) {
        eprintln!("cbor_cmd");
        let fun = ctap2::process_request;
        self.monitor_request(cid, CTAPHID_CBOR, data, fun)
    }
    fn msg_cmd(&mut self, cid: u32, data: Vec<u8>) {
        let fun = u2f::process_request;
        self.monitor_request(cid, CTAPHID_MSG, data, fun)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::crypto;
    use crate::prompt;

    #[test]
    fn initialization_packet() {
        let data = b"abcdefg";
        let msg = Message {
            cid: CTAPHID_BROADCAST_CID,
            cmd: CTAPHID_INIT,
            data: data.to_vec(),
        };
        let pkts: Vec<Pkt> = msg.packetize().collect();
        assert_eq!(pkts.len(), 1);
        let p = InitializationPacket(&pkts[0]);
        assert_eq!(p.cid(), CTAPHID_BROADCAST_CID);
        assert_eq!(p.cmd(), (false, CTAPHID_INIT));
        assert_eq!(p.data(), (7, data.as_slice()));
    }

    #[test]
    fn packetize() {
        for len in [0, 10, INIT_SIZE - 1, INIT_SIZE] {
            let data: Vec<u8> = (0..len).map(|u| u as u8).collect();
            let msg = Message::new(123, CTAPHID_PING, data.clone());
            let pkts: Vec<Pkt> = msg.packetize().collect();
            assert_eq!(pkts.len(), 1);
            let p = InitializationPacket(&pkts[0]);
            assert_eq!(p.cid(), 123);
            assert_eq!(p.cmd(), (false, CTAPHID_PING));
            assert_eq!(p.data(), (data.len(), &data[..]));
        }
        for len in [INIT_SIZE + 1, INIT_SIZE + CONT_SIZE] {
            let data: Vec<u8> = (0..len).map(|u| u as u8).collect();
            let msg = Message::new(123, CTAPHID_PING, data.clone());
            let pkts: Vec<Pkt> = msg.packetize().collect();
            assert_eq!(pkts.len(), 2);
            let p0 = InitializationPacket(&pkts[0]);
            assert_eq!(p0.cid(), 123);
            assert_eq!(p0.cmd(), (false, CTAPHID_PING));
            assert_eq!(p0.data(), (data.len(), &data[..INIT_SIZE]));
            let p1 = ContinuationPacket(&pkts[1]);
            assert_eq!(p1.cid(), 123);
            assert_eq!(p1.seq(), (true, 0));
            assert_eq!(p1.data(len - INIT_SIZE), &data[INIT_SIZE..]);
        }
    }

    fn packet_to_urb(pkt: Pkt) -> Box<URB> {
        Box::new(URB {
            endpoint: 1,
            setup: [0u8; 8],
            complete: Some(Box::new(|u, _| Ok(u.transfer_buffer))),
            transfer_buffer: Some(pkt.to_vec()),
            transfer_buffer_length: pkt.len(),
        })
    }

    #[test]
    fn assemble() {
        let (tx, rx) = mpsc::channel();
        let mut assembler = Assembler::new(Box::new(rx.into_iter()));
        for len in [
            0,
            10,
            INIT_SIZE - 1,
            INIT_SIZE,
            INIT_SIZE + 1,
            PACKET_SIZE,
            INIT_SIZE + CONT_SIZE - 1,
            INIT_SIZE + CONT_SIZE,
            INIT_SIZE + CONT_SIZE + 1,
            INIT_SIZE + 2 * CONT_SIZE,
            2 * PACKET_SIZE,
            3 * PACKET_SIZE,
        ] {
            let data: Vec<u8> = (0..len).map(|u| u as u8).collect();
            let msg = Message::new(123, CTAPHID_PING, data.clone());
            for pkt in msg.packetize() {
                tx.send(pkt).unwrap();
            }
            let msg = assembler.next().unwrap().unwrap();
            assert_eq!(msg.cid, 123);
            assert_eq!(msg.cmd, CTAPHID_PING);
            assert_eq!(msg.data, data);
        }
        std::mem::drop(tx);
        assert!(assembler.next().is_none());
    }

    type CTAPHID = (Sender<Box<URB>>, Sender<Box<URB>>);
    fn open_ctaphid() -> CTAPHID {
        let token = crypto::tests::get_token().unwrap();
        let prompt = prompt::yes_or_no_p;
        Parser::new(token, prompt)
    }

    fn send_receive_msg(ctaphid: &CTAPHID, msg: Message) -> Message {
        let (tx, rx) = mpsc::channel();
        for pkt in msg.packetize() {
            let urb = packet_to_urb(pkt);
            ctaphid.0.send(urb).unwrap();
            send_reply_urb(&tx, &ctaphid.1);
        }
        fn send_reply_urb(tx: &Sender<Box<URB>>, out: &Sender<Box<URB>>) {
            let tx = tx.clone();
            let urb = Box::new(URB {
                endpoint: 1,
                setup: [0u8; 8],
                complete: Some(Box::new(move |_urb, buf| {
                    let pkt: Pkt = buf.unwrap().try_into().unwrap();
                    let urb2 = packet_to_urb(pkt);
                    tx.send(urb2).ok();
                    Ok(None)
                })),
                transfer_buffer: None,
                transfer_buffer_length: PACKET_SIZE,
            });
            out.send(urb).unwrap();
        }
        let mut assembler = Assembler::new(Box::new(URBReceiver(rx)));
        match assembler.next() {
            Some(Ok(msg)) => return msg,
            Some(Err(e)) => panic!("assembler error: {:?}", e),
            None => panic!("assembler end of input"),
        }
    }

    fn open_channel(ctaphid: &CTAPHID) -> u32 {
        let nonce: Vec<u8> = (10..18).collect();
        let m1 = Message::new(
            CTAPHID_BROADCAST_CID,
            CTAPHID_INIT,
            nonce.clone(),
        );
        let m2 = send_receive_msg(ctaphid, m1);
        assert_eq!(m2.cid, CTAPHID_BROADCAST_CID);
        assert_eq!(m2.cmd, CTAPHID_INIT);
        let r =
            InitResponse::unpack(&m2.data.try_into().unwrap()).unwrap();
        assert_eq!(&nonce[..], &r.nonce);
        assert!(r.channelid != 0);
        assert!(r.channelid != CTAPHID_BROADCAST_CID);
        assert!(r.capabilities & CAPABILITY_CBOR != 0);
        r.channelid
    }

    #[test]
    fn alloc_channel() {
        let ctaphid = open_ctaphid();
        open_channel(&ctaphid);
    }

    #[test]
    fn ping() {
        let ctaphid = open_ctaphid();
        let cid = open_channel(&ctaphid);
        for data in [
            &b""[..],
            &b"abc"[..],
            &(0..PACKET_SIZE as u8 - 7).collect::<Vec<u8>>(),
        ] {
            let m1 = Message::new(cid, CTAPHID_PING, data.to_vec());
            let m2 = send_receive_msg(&ctaphid, m1);
            assert_eq!(m2.cid, cid);
            assert_eq!(m2.cmd, CTAPHID_PING);
            assert_eq!(m2.data, data);
        }
    }

    #[test]
    fn ping_cont() {
        let ctaphid = open_ctaphid();
        let cid = open_channel(&ctaphid);
        for len in [
            INIT_SIZE,
            INIT_SIZE + 1,
            INIT_SIZE + CONT_SIZE,
            PACKET_SIZE,
            INIT_SIZE + CONT_SIZE + 1,
            INIT_SIZE + 2 * CONT_SIZE + 1,
            3 * PACKET_SIZE,
            4 * PACKET_SIZE,
        ] {
            let data: Vec<u8> = (0..len).map(|u| u as u8).collect();
            let m1 = Message::new(cid, CTAPHID_PING, data.clone());
            let m2 = send_receive_msg(&ctaphid, m1);
            assert_eq!(m2.cid, cid);
            assert_eq!(m2.cmd, CTAPHID_PING);
            assert_eq!(m2.data, data);
        }
    }

    #[test]
    fn cbor_get_info() {
        let ctaphid = open_ctaphid();
        let cid = open_channel(&ctaphid);
        let data = [ctap2::CTAP2_GET_INFO];
        let m1 = Message::new(cid, CTAPHID_CBOR, data.to_vec());
        let m2 = send_receive_msg(&ctaphid, m1);
        assert_eq!(m2.cid, cid);
        assert_eq!(m2.cmd, CTAPHID_CBOR);
        ctap2::test::check_get_info_response(&m2.data);
    }

    #[test]
    fn u2f_get_version() {
        let ctaphid = open_ctaphid();
        let cid = open_channel(&ctaphid);
        let data = vec![0x0u8, 0x3, 0, 0, 0, 0, 0];
        let m1 = Message::new(cid, CTAPHID_MSG, data);
        let m2 = send_receive_msg(&ctaphid, m1);
        assert_eq!(m2.cid, cid);
        assert_eq!(m2.cmd, CTAPHID_MSG);
        assert_eq!(m2.data, b"U2F_V2\x90\x00")
    }
}
