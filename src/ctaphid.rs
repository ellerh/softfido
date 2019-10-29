
use crate::prompt;
use crate::crypto;
use serde::{Serialize, Serializer, Deserialize, Deserializer,
            ser::SerializeMap};
use std::error::Error;
use std::cmp::min;
use std::collections::VecDeque;
use packed_struct::PackedStruct;
use std::time::Duration;
use std::sync::mpsc::{Receiver, RecvTimeoutError};

//use packed_struct::PrimitiveEnum;

pub struct Parser<'a> {
    channel: u32,
    cmd: u8,
    bcnt: u16,
    buffer: Vec<u8>,
    seqnum: u8,
    state: fn(p:&mut Parser<'a>, pkt: &[u8]) -> Result<(), Box<Error>>,
    channel_counter: u32,
    pub send_queue: VecDeque<Vec<u8>>,
    pub recv_queue: VecDeque<Vec<u8>>,
    max_packet_size: u16,
    token: &'a crypto::KeyStore,
    env: Env,
}

enum Env {
    MakeCredential{channel:u32,
                   args: MakeCredentialArgs,
                   consent: Receiver<Result<bool, pinentry_rs::Error>>},
    GetAssertion{channel:u32,
                 args: GetAssertionArgs,
                 consent: Receiver<Result<bool, pinentry_rs::Error>>},
    None,
}

const CTAPHID_BROADCAST_CID: u32 = 0xFFFFFFFF;

const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_PING: u8 = 0x01;
const CTAPHID_CBOR: u8 = 0x10;
const CTAPHID_MSG: u8 = 0x03;
const CTAPHID_ERROR: u8 = 0x3F;
const CTAPHID_KEEPALIVE: u8 = 0x3B;

//const CAPABILITY_WINK: u8 = 0x01;
const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

const CTAP2_GET_INFO: u8 = 0x04;
const CTAP2_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP2_GET_ASSERTION: u8 = 0x02;

const STATUS_UPNEEDED: u8 = 2;

const ERR_INVALID_CMD: u8 = 0x01;
const ERR_OPERATION_DENIED: u8 = 0x27;
const ERR_INVALID_CREDENTIAL: u8 = 0x22;
const ERR_INVALID_CBOR: u8 = 0x12;

#[derive(PackedStruct, Debug)]
#[packed_struct(endian = "lsb")]
pub struct InitResponse {
    channel: u32,
    cmd: u8,
    #[packed_field(endian = "msb")]
    bcnt: u16,
    nonce: [u8; 8],
    channelid: u32,
    protocol_version: u8,
    device_major_version: u8,
    device_minor_version: u8,
    device_build_version: u8,
    capabilities: u8,
}

const AAGUID: u128 = 0x7ec96c58403748ed8e7eb2a1b538374e;
//const AAGUID: u128 = 0x0;

#[allow(dead_code)]
type Cbor = serde_cbor::value::Value;

#[derive(Debug, Serialize)]
struct GetInfoResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    _marker: Option<()>,
    versions: [String; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions: Option<Vec<String>>,
    aaguid: Bytes,
}

#[derive(Debug)]
struct Bytes (Vec<u8>);

#[derive(Debug, Deserialize)]
struct MakeCredentialArgs {
    _marker: Option<()>,
    client_data_hash: Bytes,
    rp: RelyingParty,
    user: User,
    pub_key_algs: Vec<PublicKeyCredentialParameters>,
    #[serde(default)]
    exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    extensions: Option<()>,
    #[serde(default)]
    options: MakeCredentialArgsOptions
}

#[derive(Debug, Deserialize)]
struct RelyingParty {
    id: String,
    name: String,
    icon: Option<String>
}

#[derive(Debug, Deserialize, Serialize)]
struct User {
    id: Bytes,
    #[serde(rename = "displayName")]
    display_name: String,
    name: String,
    icon: Option<String>
}

#[derive(Debug, Deserialize)]
struct PublicKeyCredentialParameters {
    r#type: String,
    alg: i32,
}

#[derive(Debug, Deserialize, Serialize)]
struct PublicKeyCredentialDescriptor {
    r#type: String,
    id: Bytes,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct MakeCredentialArgsOptions {
    rk: bool,
    uv: bool,
}

#[derive(Debug, Serialize)]
struct MakeCredentialResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    _marker: Option<()>,
    fmt: String,
    auth_data: Bytes,
    att_stmt: std::collections::BTreeMap<i8,i8>,
}

#[derive(Debug)]
struct CoseKey {
    kty: i8,
    alg: i8,
    crv: i8,
    x: Bytes,
    y: Bytes,
}

#[derive(Debug, Deserialize)]
struct GetAssertionArgs {
    _marker: Option<()>,
    rp_id: String,
    client_data_hash: Bytes,
    #[serde(default)]
    allow_list: Vec<PublicKeyCredentialDescriptor>,
    extensions: Option<()>,
    #[serde(default)]
    options: GetAssertionOptions,
}

#[derive(Debug, Deserialize, Default)]
struct GetAssertionOptions {
    #[serde(default = "up_default")]
    up: bool,
    #[serde(default)]
    uv: bool,
}
fn up_default () -> bool { return true }

#[derive(Debug, Serialize)]
struct GetAssertionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    _marker: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<PublicKeyCredentialDescriptor>,
    auth_data: Bytes,
    signature: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<User>,
    #[serde(skip_serializing_if = "Option::is_none")]
    number_of_credentials: Option<usize>
}

impl Serialize for CoseKey {
    fn serialize<S:Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
    {
        use serde_cbor::value::Value::*;
        let entries = [
            (Integer(1), Integer(self.kty as i128)),
            (Integer(3), Integer(self.alg as i128)),
            (Integer(-1), Integer(self.crv as i128)),
            (Integer(-2), Bytes(self.x.0.clone())),
            (Integer(-3), Bytes(self.y.0.clone())),
        ];
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for (k, v) in entries.iter() {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl Serialize for Bytes {
    fn serialize<S:Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes {

    fn deserialize<D>(deserializer: D) -> Result<Bytes, D::Error>
    where D:Deserializer<'de>
    {
        deserializer.deserialize_bytes(BytesVisitor)
    }
}

struct BytesVisitor;
impl<'de> serde::de::Visitor<'de> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a byte array")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where E:serde::de::Error
    {
        Ok(Bytes(v.to_vec()))
    }

}

impl<'a> Parser<'a> {

    pub fn new (max_packet_size: u16, token: &'a crypto::KeyStore) -> Self {
        Self {
            channel: 0,
            cmd: 0,
            bcnt: 0,
            buffer: Vec::<u8>::with_capacity(4096),
            state: Parser::parse_init_packet,
            channel_counter: 123456,
            send_queue: VecDeque::new(),
            recv_queue: VecDeque::new(),
            max_packet_size: max_packet_size,
            seqnum: 0,
            token: token,
            env: Env::None,
        }
    }
    
    pub fn parse (&mut self) -> Result<(), Box<Error>>{
        match self.recv_queue.pop_front() {
            None => Ok(()),
            Some(pkt) => {
                log!("parse");
                (self.state)(self, &pkt)
            }
        }
    }

    pub fn unparse (&mut self, pkt: &mut [u8]) -> Result<(), Box<Error>>{
        match self.send_queue.pop_front() {
            None => Ok(()),
            Some(r) => {
                log!("unparse");
                assert!(r.len() <= pkt.len());
                pkt[..r.len()].copy_from_slice(&r[..]);
                match self.env {
                    Env::MakeCredential{..} | Env::GetAssertion{..} => {
                        assert!(self.recv_queue.is_empty());
                        self.recv_queue.push_front(vec!());
                    }
                    Env::None => (),
                }
                Ok(())
            }
        }
    }

    fn parse_init_packet (&mut self, pkt: &[u8]) -> Result<(), Box<Error>> {
        assert!(pkt.len() >= 8);
        let channel = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        let cmd = pkt[4];
        assert!((cmd >> 7) == 1);
        let cmd = cmd & !(1 << 7);
        let bcnt = u16::from_be_bytes([pkt[5],pkt[6]]);
        let data = &pkt[7..min(pkt.len(), 7 + (bcnt as usize))];
        if data.len() == bcnt as usize {
            self.process_message(channel, cmd, data)
        } else {
            log!("init_cont: channel: {:x} bcnt: {} cmd: {}",
                 channel, bcnt, cmd);
            self.channel = channel;
            self.cmd = cmd;
            self.bcnt = bcnt;
            self.seqnum = 0;
            self.buffer.extend(data);
            self.state = Parser::parse_cont_packet;
            Ok(())
        }
    }

    fn parse_cont_packet (&mut self, pkt: &[u8])
                          -> Result<(), Box<Error>> {
        assert!(pkt.len() > 5);
        let channel = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        assert!(channel == self.channel);
        let seqnum = pkt[4];
        assert!((seqnum >> 7) == 0);
        assert!(seqnum == self.seqnum);
        let m = self.max_packet_size;
        assert!(self.buffer.len() ==
                (m - 7 + self.seqnum as u16 * (m - 5)) as usize);
        if m - 7 + (seqnum + 1) as u16 * (m - 5) < self.bcnt {
            self.seqnum = seqnum + 1;
            self.buffer.extend(&pkt[5..]);
            self.state = Parser::parse_cont_packet;
            Ok(())
        } else {
            let rest = self.bcnt as usize - self.buffer.len();
            self.buffer.extend(&pkt[5..5 + rest as usize]);
            assert!(self.buffer.len() == self.bcnt as usize);
            let mut data = vec!();
            data.append(&mut self.buffer);
            self.state = Parser::parse_init_packet;
            self.process_message(channel, self.cmd, &data)
        }
    }

    fn process_message (&mut self, channel:u32, cmd: u8, data: &[u8])
                    -> Result<(), Box<Error>> {
        log!("process_message: 0x{:x} 0x{:x}", channel, cmd);
        match cmd {
            CTAPHID_INIT => self.init_cmd (channel, data),
            CTAPHID_PING => self.ping_cmd (channel, data),
            CTAPHID_CBOR => self.cbor_cmd (channel, data),
            CTAPHID_MSG => { println!("CTAPHID_MSG (invalid)");
                             self.send_error (channel, ERR_INVALID_CMD) },
            _ => panic!("Command nyi: {}", cmd),
        }
    }

    fn init_cmd(&mut self, channel: u32, data: &[u8])
                -> Result<(), Box<Error>> {
        assert!(data.len() == 8);
        let nonce = u64::from_le_bytes([data[0], data[1], data[2], data[3],
                                        data[4], data[5], data[6], data[7],]);
        match channel {
            CTAPHID_BROADCAST_CID => self.allocate_channel(nonce),
            _ => panic!("init_channel nyi: {}", channel)
        }
    }

    fn ping_cmd(&mut self, channel: u32, data: &[u8])
                -> Result<(), Box<Error>> {
        log!("ping_cmd channel: 0x{:x} data: {}", channel,
             String::from_utf8_lossy(&data));
        // let secs = 30;
        // println!("sleeping {} secs ...", secs);
        // std::thread::sleep(std::time::Duration::from_secs(secs));
        self.send_reply(channel, CTAPHID_PING, data);
        Ok(())
    }

    fn cbor_cmd(&mut self, channel: u32, data: &[u8])
                -> Result<(), Box<Error>> {
        assert!(data.len() >= 1);
        let cmd = data[0];
        let cbor = &data[1..];
        log!("cbor_cmd channel: 0x{:x} cmd: {:?}", channel, cmd);
        match cmd {
            CTAP2_GET_INFO => self.get_info(channel, cbor),
            CTAP2_MAKE_CREDENTIAL => self.make_credential(channel, cbor),
            CTAP2_GET_ASSERTION => self.get_assertion(channel, cbor),
            _ => panic!("ctap2 command {} nyi", cmd)
        }
    }    

    fn send_reply(&mut self, channel: u32, cmd: u8, data: &[u8]) {
        let mut reply = u32::to_le_bytes(channel).to_vec();
        reply.push(cmd | (1 << 7));
        reply.extend_from_slice(&u16::to_be_bytes(data.len() as u16));
        let init_max = self.max_packet_size as usize - 7;
        if data.len() < init_max {
            reply.extend_from_slice(data);
            self.send_queue.push_back(reply)
        } else {
            reply.extend_from_slice(&data[0..init_max]);
            self.send_queue.push_back(reply);
            let cont_max = self.max_packet_size as usize - 5;
            data[init_max..].chunks(cont_max).enumerate()
                .for_each(|(i, chunk)| {
                    let mut cont = u32::to_le_bytes(channel).to_vec();
                    assert!(i < 0x7f);
                    cont.push(i as u8);
                    cont.extend_from_slice(chunk);
                    self.send_queue.push_back(cont)
                })
        }
    }

    fn send_error(&mut self, channel: u32, data: u8) ->
        Result<(), Box<Error>> {
            log!("send_error: {}", data);
            self.send_reply(channel, CTAPHID_ERROR, &[data]);
            Ok(())
    }
    
    fn allocate_channel(&mut self, nonce: u64) -> Result<(), Box<Error>> {
        let ch = self.channel_counter;
        self.channel_counter += 1;
        let response = InitResponse {
            channel: CTAPHID_BROADCAST_CID,
            cmd: CTAPHID_INIT | (1 << 7),
            bcnt: 17,
            nonce: nonce.to_le_bytes(),
            channelid: ch,
            protocol_version: 2,
            device_major_version: 0,
            device_minor_version: 0,
            device_build_version: 0,
            capabilities: CAPABILITY_CBOR|CAPABILITY_NMSG,
        };
        self.send_queue.push_back(Vec::from(&response.pack()[..]));
        Ok(())
    }

    fn get_info (&mut self, channel: u32, cbor: &[u8])
                 -> Result<(), Box<Error>> {
        log!("get_info channel: 0x{:x}", channel);
        assert!(cbor.len() == 0);
        let reply = GetInfoResponse {
            _marker: None,
            versions: ["FIDO_2_0".to_owned()],
            aaguid: Bytes(AAGUID.to_le_bytes().to_vec()),
            extensions: None,
        };
        let cbor = serde_cbor::ser::to_vec_packed(&reply)?;
        self.send_cbor_reply(channel, &cbor);
        Ok(())
    }

    fn send_cbor_reply(&mut self, channel: u32, cbor: &[u8]) {
        let mut data = vec!(0);
        data.extend_from_slice(cbor);
        self.send_reply(channel, CTAPHID_CBOR, &data);
    }
    
    fn make_credential (&mut self, channel: u32, cbor: &[u8])
                        -> Result<(), Box<Error>> {
        let args = match serde_cbor::from_slice::<MakeCredentialArgs>(cbor) {
            Ok(args) => args,
            Err(err) => {
                log!("can't parse make_credential args: {}", err);
                return self.send_error(channel, ERR_INVALID_CBOR)
            }
        };
        log!("CTAP2_MAKE_CREDENTIAL 0x{:x} {}", channel, args.rp.id);
        assert!(args.user.id.0.len() <= 64);
        match &args.pub_key_algs[0] {
            PublicKeyCredentialParameters{alg: -7, r#type: t}
            if t == "public-key" => (),
            x => panic!("crypto alg not supported: {:?}", x),
        };
        let prompt = format!(
            "Consent needed for creating registration credentials

  Relying Party: {} ({})
  User: {} ({})

Allow? ",
            &args.rp.id, &args.rp.name, &args.user.name,
            &args.user.display_name);
        let x = prompt::yes_or_no_p(&prompt);
        self.env = Env::MakeCredential{ channel: channel, args: args,
                                        consent: x };
        self.state = Parser::make_credential_cont;
        self.make_credential_2()
    }
        
    fn make_credential_2 (&mut self) -> Result<(), Box<Error>>
    {
        let (channel, consent) = match &self.env {
            Env::MakeCredential{ channel, consent, .. } => (*channel, consent),
            _ => panic!()
        };
        let r = match consent.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(true)) => self.make_credential_3(),
            Ok(Ok(false)) | Err(RecvTimeoutError::Disconnected) =>
                self.send_error (channel, ERR_OPERATION_DENIED),
            Ok(Err(e)) => panic!("Receive consent: {:?}", e),
            Err(RecvTimeoutError::Timeout) => {
                self.send_reply(channel, CTAPHID_KEEPALIVE,
                                &[STATUS_UPNEEDED][..]);
                return Ok(())
            },
        };
        self.state = Parser::parse_init_packet;
        self.env = Env::None;
        r
    }

    fn make_credential_3 (&mut self) -> Result<(), Box<Error>>
    {
        let (privk, pubk) = self.token.generate_key_pair()
            .unwrap_or_else(|e| panic!("generate_key_pair failed: {}", e));
        let (channel, args) = match &self.env {
            Env::MakeCredential { channel, args, .. } => (*channel,args),
            _ => panic!()
        };
        assert!(!args.options.rk);
        let auth_data: Vec<u8> = [
            &crypto::sha256_hash(args.rp.id.as_bytes())[..],
            &vec!(1|1<<6), // flags
            &0u32.to_be_bytes(), //counter
            &AAGUID.to_le_bytes(),
            &(privk.len() as u16).to_be_bytes(),
            &privk,
            &serde_cbor::ser::to_vec_packed(&CoseKey {
                kty: 2, alg: -7, crv: 1,
                x: Bytes(pubk.0),
                y: Bytes(pubk.1)
            })?
        ].concat();
        let att_obj = MakeCredentialResponse {
            _marker: None,
            fmt: "none".to_string(),
            auth_data: Bytes(auth_data),
            att_stmt: std::collections::BTreeMap::new(),
        };
        let cbor = serde_cbor::ser::to_vec_packed(&att_obj)?;
        self.send_cbor_reply(channel, &cbor);
        Ok(())
    }

    fn make_credential_cont (&mut self, pkt: &[u8])
                             -> Result<(), Box<Error>> {
        log!("make_credential_cont");
        assert!(pkt.len() == 0);
        self.make_credential_2()
    }

    fn get_assertion (&mut self, channel: u32, cbor: &[u8])
                      -> Result<(), Box<Error>> {
        let args: GetAssertionArgs = serde_cbor::from_slice(cbor).unwrap();
        log!("get_assertion 0x{:x} {}", channel, args.rp_id);
        assert!(args.allow_list.len() == 1);
        let privk = &args.allow_list[0].id;
        if !self.token.is_valid_id(&privk.0) {
            return self.send_error (channel, ERR_INVALID_CREDENTIAL)
        };
        let prompt = format!(
            "Consent needed for signing challange

  Relying Party: {}

Allow?",
            &args.rp_id);
        let x = prompt::yes_or_no_p(&prompt);
        self.env = Env::GetAssertion{ channel: channel, args: args,
                                      consent: x };
        self.state = Parser::get_assertion_cont;
        self.get_assertion_2 ()
    }

    // FIXME: almost the same as make_credential_2
    fn get_assertion_2 (&mut self) -> Result<(), Box<Error>>
    {
        let (channel, consent) = match &self.env {
            Env::GetAssertion{ channel, consent, .. } => (*channel, consent),
            _ => panic!()
        };
        let r = match consent.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(true)) => self.get_assertion_3(),
            Ok(Ok(false)) | Err(RecvTimeoutError::Disconnected) =>
                self.send_error (channel, ERR_OPERATION_DENIED),
            Ok(Err(e)) => panic!("Receive consent: {:?}", e),
            Err(RecvTimeoutError::Timeout) => {
                self.send_reply(channel, CTAPHID_KEEPALIVE,
                                &[STATUS_UPNEEDED][..]);
                return Ok(())
            },
        };
        self.state = Parser::parse_init_packet;
        self.env = Env::None;
        r
    }
    
    fn get_assertion_3 (&mut self) -> Result<(), Box<Error>> {
        let (channel, args) = match &self.env {
            Env::GetAssertion { channel, args, .. } => (*channel,args),
            _ => panic!()
        };
        let privk = &args.allow_list[0].id;
        let auth_data: Vec<u8> = [
            &crypto::sha256_hash(args.rp_id.as_bytes())[..],
            &vec!(1<<0|0<<6), // flags
            &0u32.to_be_bytes(), //counter
        ].concat();
        let data = [&auth_data[..], &args.client_data_hash.0[..]].concat();
        let signature = self.token.sign(&privk.0, &data)?;
        let response = GetAssertionResponse {
            _marker: None,
            auth_data: Bytes(auth_data),
            signature: Bytes(signature),
            credential: None,
            number_of_credentials: None,
            user: None,
        };
        let cbor = serde_cbor::ser::to_vec_packed(&response)?;
        self.send_cbor_reply(channel, &cbor);
        Ok(())
    }
    
    fn get_assertion_cont (&mut self, pkt: &[u8])
                           -> Result<(), Box<Error>> {
        log!("get_assertion_cont");
        assert!(pkt.len() == 0);
        self.get_assertion_2()
    }
}
