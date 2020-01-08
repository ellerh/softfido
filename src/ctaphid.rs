
use crate::prompt;
use crate::crypto;
use serde::{Serialize, Serializer, Deserialize, Deserializer,
            ser::SerializeMap};
use std::cmp::min;
use std::collections::VecDeque;
use packed_struct::PackedStruct;
use std::time::Duration;
use std::sync::mpsc::{Receiver, RecvTimeoutError};

type R<T> = Result<T, Box<dyn std::error::Error>>;
type Q = VecDeque<Vec<u8>>;

pub struct Parser<'a> {
    pub send_queue: Q,
    pub recv_queue: Q,
    token: &'a crypto::KeyStore<'a>,
    channels: Vec<Channel<'a>>
}

struct Channel<'a> {
    cid: u32,
    token: &'a crypto::KeyStore<'a>,
    state: State,  
}

#[derive(Debug)]
enum State {
    Init,
    Cont {cmd: u8, bcnt: u16, buffer: Vec<u8>, seqnum: u8},
    MakeCredential {args: MakeCredentialArgs,
                    consent: Receiver<Result<bool, pinentry_rs::Error>>},
    GetAssertion {args: GetAssertionArgs,
                  consent: Receiver<Result<bool, pinentry_rs::Error>>},
}

// struct Channel<'a> {
//     id: u32,
//     parser: &'a mut Parser<'a>,
//     state: Box<dyn Fn(&mut Channel<'a>, &[u8]) -> R<()>>
// }

// enum Env {
//     MakeCredential{channel:u32,
//                    args: MakeCredentialArgs,
//                    consent: Receiver<Result<bool, pinentry_rs::Error>>},
//     GetAssertion{channel:u32,
//                  args: GetAssertionArgs,
//                  consent: Receiver<Result<bool, pinentry_rs::Error>>},
//     None,
// }

const MAX_PACKET_SIZE: u16 = 64;

const CTAPHID_BROADCAST_CID: u32 = 0xFFFFFFFF;

const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_PING: u8 = 0x01;
const CTAPHID_CANCEL: u8 = 0x11;
const CTAPHID_CBOR: u8 = 0x10;
const CTAPHID_MSG: u8 = 0x03;
const CTAPHID_ERROR: u8 = 0x3F;
const CTAPHID_KEEPALIVE: u8 = 0x3B;
const CTAPHID_VENDOR_FIRST: u8 = (0x40);
const HACK_CHECK_STATUS: u8 = CTAPHID_VENDOR_FIRST + 10;

//const CAPABILITY_WINK: u8 = 0x01;
const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

const CTAP1_ERR_SUCCESS: u8 = 0x00;
const CTAP2_GET_INFO: u8 = 0x04;
const CTAP2_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP2_GET_ASSERTION: u8 = 0x02;

const STATUS_UPNEEDED: u8 = 2;

const ERR_INVALID_CMD: u8 = 0x01;
const ERR_INVALID_PAR: u8 = 0x02;
#[allow(dead_code)]
const ERR_BUSY: u8 = 0x06;
#[allow(dead_code)]
const ERR_INVALID_CHANNEL: u8 =	0x0B;
const ERR_OPERATION_DENIED: u8 = 0x27;
const ERR_INVALID_CREDENTIAL: u8 = 0x22;
//const ERR_INVALID_OPTION: u8 = 0x2C;
const ERR_INVALID_CBOR: u8 = 0x12;
#[allow(dead_code)]
const ERR_KEEPALIVE_CANCEL: u8 = 0x2D;

const SW_NO_ERROR: u16 = 0x9000;
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
//const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
const SW_WRONG_DATA: u16 = 0x6A80;

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
    versions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions: Option<Vec<String>>,
    aaguid: Bytes,
}

#[derive(Debug, Clone)]
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
    name: Option<String>,
    icon: Option<String>
}

#[derive(Debug, Deserialize, Serialize)]
struct User {
    id: Bytes,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    name: Option<String>,
    icon: Option<String>
}

#[derive(Debug, Deserialize)]
struct PublicKeyCredentialParameters {
    r#type: String,
    alg: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct PublicKeyCredentialDescriptor {
    r#type: String,
    id: Bytes,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    #[serde(default = "options_default")]
    options: GetAssertionOptions,
}

#[derive(Debug, Deserialize, Default)]
struct GetAssertionOptions {
    #[serde(default = "up_default")]
    up: bool,
    #[serde(default)]
    uv: bool,
}
fn options_default () -> GetAssertionOptions {
    GetAssertionOptions{up: true, uv: false}
}
fn up_default () -> bool { options_default().up }

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

#[derive(Debug, Serialize, Deserialize)]
struct CredentialId {
    wrapped_private_key: Bytes,
    encrypted_rp_id: Bytes,
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

    pub fn new (token: &'a crypto::KeyStore) -> Self {
        Self {
            channels: vec![],
            send_queue: VecDeque::new(),
            recv_queue: VecDeque::new(),
            token: token,
        }
    }

    pub fn parse (&mut self) -> R<()>{
        match &self.recv_queue.pop_front() {
            None => Ok(()),
            Some(pkt) => {
                log!("parse");
                assert!(pkt.len() >= 7);
                let cid = u32::from_le_bytes([pkt[0], pkt[1],
                                              pkt[2], pkt[3]]);
                const ALLOC_CHANNEL: u8 = CTAPHID_INIT | (1<<7);
                match (cid, pkt[4]) {
                    (CTAPHID_BROADCAST_CID, ALLOC_CHANNEL) =>
                        self.init_cmd (cid, pkt),
                    (CTAPHID_BROADCAST_CID, _) =>
                        panic!("Invalid command for broadcast cid"),
                    (cid, _) => self.channels[cid as usize]
                        .parse(pkt, &mut self.send_queue),
                }
            }
        }
    }

    pub fn unparse (&mut self, pkt: &mut [u8]) -> R<()>{
        match self.send_queue.pop_front() {
            None => Ok(()),
            Some(r) => {
                log!("unparse");
                assert!(r.len() <= pkt.len());
                pkt[..r.len()].copy_from_slice(&r[..]);
                for channel in &self.channels {
                    match channel.state {
                        State::MakeCredential{..} |
                        State::GetAssertion{..} => {
                            assert!(self.recv_queue.len() <
                                    self.channels.len());
                            self.recv_queue.push_front(
                                [&channel.cid.to_le_bytes()[..],
                                 &[HACK_CHECK_STATUS|1<<7, 0, 0][..]]
                                    .concat());
                        },
                        State::Init | State::Cont {..}=> (),
                    }
                }
                Ok(())
            }
        }
    }

    fn init_cmd(&mut self, channel: u32, pkt: &[u8]) -> R<()> {
        log!("init_cmd");
        let bcnt = u16::from_be_bytes([pkt[5],pkt[6]]);
        let data = &pkt[7..min(pkt.len(), 7 + (bcnt as usize))];
        assert!(data.len() == 8);
        let nonce = u64::from_le_bytes([data[0], data[1], data[2], data[3],
                                        data[4], data[5], data[6], data[7],]);
        match channel {
            CTAPHID_BROADCAST_CID => self.allocate_channel(nonce),
            _ => panic!("init_channel nyi: {}", channel)
        }
    }
    
    fn allocate_channel(&mut self, nonce: u64) -> R<()> {
        let cid = self.channels.len() as u32;
        let channel = Channel::<'a>{ cid: cid,
                                     state: State::Init,
                                     token: self.token,
        };
        self.channels.push(channel);
        let response = InitResponse {
            channel: CTAPHID_BROADCAST_CID,
            cmd: CTAPHID_INIT | (1 << 7),
            bcnt: 17,
            nonce: nonce.to_le_bytes(),
            channelid: cid,
            protocol_version: 2,
            device_major_version: 0,
            device_minor_version: 0,
            device_build_version: 0,
            capabilities: CAPABILITY_CBOR & !CAPABILITY_NMSG,
        };
        self.send_queue.push_back(Vec::from(&response.pack()[..]));
        Ok(())
    }

}

fn send_reply(queue: &mut Q, channel: u32, cmd: u8, data: &[u8]) -> R<()> {
    let mut reply = u32::to_le_bytes(channel).to_vec();
    reply.push(cmd | (1 << 7));
    reply.extend_from_slice(&u16::to_be_bytes(data.len() as u16));
    let init_max = MAX_PACKET_SIZE as usize - 7;
    if data.len() < init_max {
        reply.extend_from_slice(data);
        queue.push_back(reply);
    } else {
        reply.extend_from_slice(&data[0..init_max]);
        queue.push_back(reply);
        let cont_max = MAX_PACKET_SIZE as usize - 5;
        data[init_max..].chunks(cont_max).enumerate()
            .for_each(|(i, chunk)| {
                let mut cont = u32::to_le_bytes(channel).to_vec();
                assert!(i < 0x7f);
                cont.push(i as u8);
                cont.extend_from_slice(chunk);
                queue.push_back(cont);
            })
    };
    Ok(())
}

impl<'a> Channel<'a> {

    fn parse (&mut self, pkt: &[u8], q: &mut Q) -> R<()> {
        use State::*;
        match &self.state {
            Init => self.init_state(pkt, q),
            Cont{..} => self.cont_state(pkt, q),
            MakeCredential{..} => self.make_credential_state(pkt, q),
            GetAssertion{..} => self.get_assertion_state(pkt, q),
            //s => panic!("nyi: {:?}", s)
        }
    }
    
    // FIXME: return None in case of error
    fn parse_packet(pkt: &[u8]) -> (u32, u8, u16, &[u8]) {
        assert!(pkt.len() >= 7);
        let channel = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        let cmd = pkt[4];
        assert!((cmd >> 7) == 1);
        let cmd = cmd & !(1 << 7);
        let bcnt = u16::from_be_bytes([pkt[5],pkt[6]]);
        let data = &pkt[7..min(pkt.len(), 7 + (bcnt as usize))];
        (channel, cmd, bcnt, data)
    }

    fn init_state (&mut self, pkt: &[u8], q: &mut Q) -> R<()> {
        assert!(pkt.len() >= 8);
        let cid = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        assert!(cid == self.cid);
        let cmd = pkt[4];
        assert!((cmd >> 7) == 1);
        let cmd = cmd & !(1 << 7);
        let bcnt = u16::from_be_bytes([pkt[5],pkt[6]]);
        let data = &pkt[7..min(pkt.len(), 7 + (bcnt as usize))];
        if data.len() == bcnt as usize {
            self.process_message(cmd, data, q)
        } else {
            log!("init_cont: cid: {:x} bcnt: {} cmd: {}", self.cid, bcnt, cmd);
            self.state = State::Cont{ cmd: cmd, bcnt: bcnt,
                                      seqnum: 0, buffer: data.to_vec() };
            Ok(())
        }
    }

    fn cont_state (&mut self, pkt: &[u8], q: &mut Q) -> R<()> {
        if let State::Cont{ seqnum, buffer, bcnt, cmd } = &mut self.state {
            assert!(pkt.len() > 5);
            let cid = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
            assert!(cid == self.cid);
            let lseqnum = pkt[4];
            assert!((lseqnum >> 7) == 0);
            assert!(lseqnum == *seqnum);
            let m = MAX_PACKET_SIZE;
            assert!(buffer.len() ==
                    (m - 7 + lseqnum as u16 * (m - 5)) as usize);
            if m - 7 + (lseqnum + 1) as u16 * (m - 5) < *bcnt {
                *seqnum = lseqnum + 1;
                buffer.extend(&pkt[5..]);
                Ok(())
            } else {
                let rest = *bcnt as usize - buffer.len();
                buffer.extend(&pkt[5..5 + rest as usize]);
                assert!(buffer.len() == *bcnt as usize);
                let cmd = *cmd;
                let data = buffer.clone();
                self.state = State::Init;
                self.process_message(cmd, &data, q)
            }
        } else { panic!() }
    }

    fn process_message (&mut self, cmd: u8, data: &[u8], q: &mut Q) -> R<()> {
        log!("process_message: 0x{:x}", cmd);
        match cmd {
            //CTAPHID_INIT => self.init_cmd (data),
            CTAPHID_PING => self.ping_cmd(data, q),
            CTAPHID_CBOR => self.cbor_cmd(data, q),
            CTAPHID_MSG => self.msg_cmd(data, q),
            CTAPHID_CANCEL => Ok(()), // Ignored, as per spec.
            _ => {
                let _ = self.send_error (ERR_INVALID_CMD, q);
                panic!("Command nyi: {}", cmd)
            },
        }
    }

    fn ping_cmd(&mut self, data: &[u8], q: &mut Q) -> R<()> {
        log!("ping_cmd data: {}", String::from_utf8_lossy(&data));
        send_reply(q, self.cid, CTAPHID_PING, data)
    }

    fn cbor_cmd(&mut self, data: &[u8], q: &mut Q) -> R<()> {
        assert!(data.len() >= 1);
        let cmd = data[0];
        let cbor = &data[1..];
        log!("cbor_cmd cmd: {:?}", cmd);
        match cmd {
            CTAP2_GET_INFO => self.get_info(cbor, q),
            CTAP2_MAKE_CREDENTIAL => self.make_credential(cbor, q),
            CTAP2_GET_ASSERTION => self.get_assertion(cbor, q),
            _ => panic!("ctap2 command {} nyi", cmd)
        }
    }

    fn send_error(&mut self, data: u8, q: &mut Q) -> R<()> {
        log!("send_error: {}", data);
        send_reply(q, self.cid, CTAPHID_ERROR, &[data])
    }

    fn get_info (&mut self, cbor: &[u8], q: &mut Q) -> R<()> {
        log!("get_info");
        assert!(cbor.len() == 0);
        let reply = GetInfoResponse {
            _marker: None,
            versions: vec!["FIDO_2_0".to_owned(),  "U2F_V2".to_owned()],
            aaguid: Bytes(AAGUID.to_le_bytes().to_vec()),
            extensions: None,
        };
        let cbor = serde_cbor::ser::to_vec_packed(&reply)?;
        return self.send_cbor_reply(&cbor, q)
    }

    fn send_cbor_reply(&mut self, cbor: &[u8], q: &mut Q) -> R<()> {
        let status = CTAP1_ERR_SUCCESS;
        let mut data = vec!(status);
        data.extend_from_slice(cbor);
        send_reply(q, self.cid, CTAPHID_CBOR, &data)
    }
    
    fn send_cbor_error(&mut self, error: u8, q: &mut Q) -> R<()> {
        send_reply(q, self.cid, CTAPHID_CBOR, &[error])
    }

    fn make_credential (&mut self, cbor: &[u8], q: &mut Q) -> R<()> {
        let args = match serde_cbor::from_slice::<MakeCredentialArgs>(cbor) {
            Ok(args) => args,
            Err(err) => {
                log!("can't parse make_credential args: {}", err);
                return self.send_cbor_error(ERR_INVALID_CBOR, q);
            }
        };
        log!("CTAP2_MAKE_CREDENTIAL {}", args.rp.id);
        assert!(args.user.id.0.len() <= 64);
        match &args.pub_key_algs[0] {
            PublicKeyCredentialParameters{alg: -7, r#type: t}
            if t == "public-key" => (),
            x => panic!("crypto alg not supported: {:?}", x),
        };
        let prompt = format!(
            "Consent needed for creating registration credentials

  Relying Party: {} ({:?})
  User: {:?} ({:?})

Allow? ",
            &args.rp.id, &args.rp.name,
            &args.user.name, &args.user.display_name);
        let x = prompt::yes_or_no_p(&prompt);
        self.state = State::MakeCredential{ args: args, consent: x };
        self.make_credential_2(q)
    }

    fn make_credential_2 (&mut self, q: &mut Q) -> R<()> {
        let consent = match &self.state {
            State::MakeCredential{ consent, .. } => consent,
            _ => panic!()
        };
        let r = match consent.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(true)) => self.make_credential_3(q),
            Ok(Ok(false)) | Err(RecvTimeoutError::Disconnected) =>
                self.send_cbor_error (ERR_OPERATION_DENIED, q),
            Ok(Err(e)) => panic!("Receive consent: {:?}", e),
            Err(RecvTimeoutError::Timeout) => 
                return send_reply(q, self.cid, CTAPHID_KEEPALIVE,
                                  &[STATUS_UPNEEDED][..]),
        };
        self.state = State::Init;
        r
    }

    fn build_auth_data(&self, rp_id: &[u8],
                       wrapped_priv_key: &[u8],
                       pub_key_cose: &[u8]) -> R<Vec<u8>> {
        let counter: u32 = self.token.increment_token_counter()?;
        let flags: u8 = 1<<0|1<<6;
        let credential_id = serde_cbor::ser::to_vec_packed(&CredentialId{
            wrapped_private_key: Bytes(wrapped_priv_key.to_vec()),
            encrypted_rp_id: Bytes(self.token.encrypt(&rp_id)?),
        })?;
        Ok([&crypto::sha256_hash(rp_id)[..],
            &[flags],
            &counter.to_be_bytes(),
            &AAGUID.to_le_bytes(),
            &(credential_id.len() as u16).to_be_bytes(),
            &credential_id,
            pub_key_cose
        ].concat())
    }

    fn make_credential_3 (&mut self, q: &mut Q) -> R<()>
    {
        let (privk, pubk) = self.token.generate_key_pair()
            .unwrap_or_else(|e| panic!("generate_key_pair failed: {}", e));
        let args = match &self.state {
            State::MakeCredential { args, .. } => args,
            _ => panic!()
        };
        assert!(!args.options.rk);
        let pub_key_cose = serde_cbor::ser::to_vec_packed(&CoseKey {
                kty: 2, alg: -7, crv: 1,
                x: Bytes(pubk.0),
                y: Bytes(pubk.1)
        })?;
        let auth_data = self.build_auth_data(args.rp.id.as_bytes(),
                                             &privk, &pub_key_cose)?;
        let att_obj = MakeCredentialResponse {
            _marker: None,
            fmt: "none".to_string(),
            auth_data: Bytes(auth_data),
            att_stmt: std::collections::BTreeMap::new(),
        };
        let cbor = serde_cbor::ser::to_vec_packed(&att_obj)?;
        self.send_cbor_reply(&cbor, q)
    }

    fn make_credential_state (&mut self, pkt: &[u8], q: &mut Q) -> R<()> {
        log!("make_credential_state");
        match Self::parse_packet(pkt) {
            (_, HACK_CHECK_STATUS, 0, _) => self.make_credential_2(q),
            (_, CTAPHID_CANCEL, 0, _) => self.make_credential_cancel(q),
            (_cid, cmd, bcnt, data) =>
                panic!("unexpected pkg: cmd: {:x} bcnt: {} data: {:?}",
                       cmd, bcnt, data)
        }
    }

    fn make_credential_cancel (&mut self, q: &mut Q) -> R<()> {
        self.state = State::Init;
        self.send_cbor_error (ERR_KEEPALIVE_CANCEL, q)
    }
    
    fn get_assertion (&mut self, cbor: &[u8], q: &mut Q) -> R<()> {
        let args: GetAssertionArgs = match serde_cbor::from_slice(cbor) {
            Ok(x) => x,
            Err(e) => {
                log!("failed to parse cbor: {}", e);
                return self.send_error(ERR_INVALID_PAR, q)
            }
        };
        log!("get_assertion {:?}", args);
        assert!(args.allow_list.len() == 1);
        let credential_id: CredentialId = match serde_cbor::from_slice
            (&args.allow_list[0].id.0) {
                Ok(x) => x,
                Err(_) => return self.send_cbor_error(ERR_INVALID_CREDENTIAL,
                                                      q)
            };
        match (self.token.decrypt(&credential_id.encrypted_rp_id.0),
               args.rp_id.as_bytes()) {
            (Ok(id1), id2) if id1 == id2 => (),
            _ => return self.send_cbor_error(ERR_INVALID_CREDENTIAL, q),
        };
        let prompt = format!(
            "Consent needed for signing challange

  Relying Party: {}

Allow?",
            &args.rp_id);
        let x = prompt::yes_or_no_p(&prompt);
        self.state = State::GetAssertion{ args: args, consent: x };
        self.get_assertion_2 (q)
    }

    // FIXME: almost the same as make_credential_2
    fn get_assertion_2 (&mut self, q: &mut Q) -> R<()>
    {
        let consent = match &self.state {
            State::GetAssertion{ consent, .. } => consent,
            _ => panic!()
        };
        let r = match consent.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(true)) => self.get_assertion_3(q),
            Ok(Ok(false)) | Err(RecvTimeoutError::Disconnected) =>
                self.send_cbor_error (ERR_OPERATION_DENIED, q),
            Ok(Err(e)) => panic!("Receive consent: {:?}", e),
            Err(RecvTimeoutError::Timeout) =>
                return send_reply(q, self.cid, CTAPHID_KEEPALIVE,
                                  &[STATUS_UPNEEDED][..]),
        };
        self.state = State::Init;
        r
    }

    fn get_assertion_3 (&mut self, q: &mut Q) -> R<()> {
        let args = match &self.state {
            State::GetAssertion { args, .. } => args,
            _ => panic!()
        };
        let credential_id = serde_cbor::from_slice::<CredentialId>
            (&args.allow_list[0].id.0).unwrap();
        let wpriv_key = &credential_id.wrapped_private_key.0;
        let counter = self.token.increment_token_counter()?;
        let auth_data: Vec<u8> = [
            &crypto::sha256_hash(args.rp_id.as_bytes())[..],
            &vec!(1<<0|  // User Present (UP) result
                  0<<6), // Attested credential data included (AT).
            &counter.to_be_bytes(),
        ].concat();
        let data = [&auth_data[..], &args.client_data_hash.0].concat();
        let signature = self.token.sign(wpriv_key, &data)?;
        let response = GetAssertionResponse {
            _marker: None,
            auth_data: Bytes(auth_data),
            signature: Bytes(signature),
            credential: None,
            number_of_credentials: Some(1),
            user: None,
        };
        let cbor = serde_cbor::ser::to_vec_packed(&response)?;
        self.send_cbor_reply(&cbor, q)
    }

    fn get_assertion_state (&mut self, pkt: &[u8], q: &mut Q) -> R<()> {
        log!("get_assertion_state");
        match Self::parse_packet(pkt) {
            (_, HACK_CHECK_STATUS, 0, _) => self.get_assertion_2(q),
            //(_, CTAPHID_CANCEL, 0, _) => self.get_credential_cancel(q),
            (_cid, cmd, bcnt, data) =>
                panic!("unexpected pkg: cmd: {:x} bcnt: {} data: {:?}",
                       cmd, bcnt, data)
        }
    }

    fn msg_cmd(&mut self, data: &[u8], q: &mut Q) -> R<()> {
        log!("msg_cmd");
        fn payload (data: &[u8]) -> Option<(u16, &[u8], u16)> {
            match data[..3] {
                [0, n2, n1] => {
                    let nc = u16::from_be_bytes([n2, n1]);
                    let end = 3+nc as usize;
                    let lc = match data[end..] {
                        [l2, l1] => u16::from_be_bytes([l2, l1]),
                        _ => return None
                    };
                    Some((nc, &data[3..end], lc))
                },
                _ => None
            }
        };
        match (&data[..4], payload (&data[4..])) {
            ([0, 3, 0, 0], Some(( 0, _, 0))) => self.u2f_version(q),
            ([0, 1, p1,0], Some((64, d, 0))) if [0, 3].contains(&p1) =>
                self.u2f_register(d, q),
            ([0, 2, p1,0], Some((_, d, 0))) if [3,7,8].contains(&p1) =>
                self.u2f_authenticate(*p1, d, q),
            _ => panic!("msg_cmd nyi {:?}", data)
        }
    }

    fn u2f_version(&mut self, q: &mut Q) -> R<()> {
        let data: Vec<u8> = ["U2F_V2".as_bytes(),
                             &SW_NO_ERROR.to_be_bytes()].concat();
        log!("u2f_version => {:?}", &data);
        send_reply(q, self.cid, CTAPHID_MSG, &data)
    }

    fn u2f_register(&mut self, data: &[u8], q: &mut Q) -> R<()> {
        log!("u2f_register: {:?}", &data);
        assert!(data.len() == 64);
        let challenge = &data[0..32];
        let application = &data[32..];
        let consent = prompt::yes_or_no_p("Allow U2F registeration?");
        match consent.recv_timeout(Duration::from_millis(10000)) {
            Ok(Ok(true)) => (),
            Ok(Ok(false)) |
            Err(RecvTimeoutError::Disconnected) |
            Err(RecvTimeoutError::Timeout) => 
                return send_reply(q, self.cid, CTAPHID_MSG,
                                  &SW_CONDITIONS_NOT_SATISFIED.to_be_bytes()),
            Ok(Err(e)) => panic!("Receive consent: {:?}", e),
        }
        let (wpriv, (x, y)) = self.token.generate_key_pair()?;
        let pub_key = [&[4u8][..], &x, &y].concat();
        assert!(pub_key.len() == 65);
        assert!(wpriv.len() <= 255);
        let credential_id = CredentialId {
            wrapped_private_key: Bytes(wpriv.clone()),
            encrypted_rp_id: Bytes(self.token.encrypt(&application)?),
        };
        println!("credential_id: {:?}", &credential_id);
        println!("application: {:?}", &application);
        let key_handle = serde_cbor::ser::to_vec_packed(&credential_id)?;
        let signature = self.token.sign(&wpriv,
                                        &[&[0u8][..],
                                          application,
                                          challenge,
                                          &key_handle,
                                          &pub_key,].concat())?;
        let not_before = chrono::Utc::now();
        let not_after = not_before + chrono::Duration::days(30);
        let cert = self.token.create_certificate(&wpriv, &pub_key,
                                                 "Fakecompany", "Fakecompany",
                                                 not_before, Some(not_after))?;
        let result = [&[5u8][..], // reserved byte 5
                      &pub_key,
                      &[key_handle.len() as u8],
                      &key_handle,
                      &cert,
                      &signature,
                      &SW_NO_ERROR.to_be_bytes()].concat();
        send_reply(q, self.cid, CTAPHID_MSG, &result)
    }

    fn u2f_authenticate(&mut self, control: u8, data: &[u8], q: &mut Q)
                        -> R<()> {
        log!("u2f_authenticate: 0x{:0x} {:?}", control, &data);
        let challange = &data[..32];
        let application = &data[32..64];
        let l = data[64];
        let key_handle = &data[65..];
        assert!(key_handle.len() == l as usize);
        let credential_id: CredentialId =
            match serde_cbor::from_slice (key_handle) {
                Ok(x) => x,
                _ => return send_reply(q, self.cid, CTAPHID_MSG,
                                       &SW_WRONG_DATA.to_be_bytes()),
            };
        println!("credential_id = {:?}", &credential_id);
        println!("application: {:?}", &application);
        let wpriv = &credential_id.wrapped_private_key.0;
        assert!(self.token.is_valid_id(wpriv));
        match self.token.decrypt(&credential_id.encrypted_rp_id.0) {
            Ok(rp_id) if rp_id == application => (),
            _ => return send_reply(q, self.cid, CTAPHID_MSG,
                                   &SW_WRONG_DATA.to_be_bytes()),
        };
        match control {
            7 => {
                let code = SW_CONDITIONS_NOT_SATISFIED;
                send_reply(q, self.cid, CTAPHID_MSG, &code.to_be_bytes())
            },
            3 => {
                let consent = prompt::yes_or_no_p("Allow U2F authentication?");
                match consent.recv_timeout(Duration::from_millis(10000)) {
                    Ok(Ok(true)) => (),
                    Ok(Ok(false)) |
                    Err(RecvTimeoutError::Disconnected) |
                    Err(RecvTimeoutError::Timeout) => {
                        return send_reply(q, self.cid, CTAPHID_MSG,
                                          &SW_CONDITIONS_NOT_SATISFIED
                                          .to_be_bytes())
                    },
                    Ok(Err(e)) => panic!("Receive consent: {:?}", e),
                }
                let presence = 1u8;
                let counter = self.token.increment_token_counter()?;
                let sig = self.token.sign(wpriv,
                                          &[application,
                                            &[presence],
                                            &counter.to_be_bytes(),
                                            challange,].concat())?;

                let reply = [&[presence][..],
                             &counter.to_be_bytes(),
                             &sig,
                             &SW_NO_ERROR.to_be_bytes()].concat();
                send_reply(q, self.cid, CTAPHID_MSG, &reply)
            }
            _ => panic!("control byte 0x{:0x} nyi", control),
        }
    }

}
