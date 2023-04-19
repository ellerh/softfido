use crate::crypto::Token;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type GetConsent<'a> = &'a dyn Fn(String) -> Result<bool, ()>;

struct CTAP2<'a> {
    get_consent: GetConsent<'a>,
    token: Token,
}

type C2R = Result<Vec<u8>, u8>;

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
struct GetInfoResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    _padding: Option<()>,
    versions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    // extensions was optional in FIDO_2.0 but is required for FIDO_2.2
    extensions: Option<Vec<String>>,
    aaguid: Bytes,
}

#[derive(Debug, Clone)]
pub struct Bytes(pub Vec<u8>);

#[derive(Debug, Deserialize)]
struct MakeCredentialArgs {
    _padding: Option<()>,
    #[allow(dead_code)]
    client_data_hash: Bytes,
    rp: RelyingParty,
    user: User,
    pub_key_algs: Vec<PublicKeyCredentialParameters>,
    #[serde(default)]
    #[allow(dead_code)]
    exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    #[allow(dead_code)]
    extensions: Option<()>,
    #[serde(default)]
    options: MakeCredentialArgsOptions,
}

#[derive(Debug, Deserialize)]
struct RelyingParty {
    id: String,
    name: Option<String>,
    #[allow(dead_code)]
    icon: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct User {
    id: Bytes,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    name: Option<String>,
    icon: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PublicKeyCredentialParameters {
    r#type: String,
    alg: i32,
}

#[derive(Debug, Deserialize, Clone)]
struct PublicKeyCredentialDescriptor {
    r#type: String,
    id: Bytes,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct MakeCredentialArgsOptions {
    rk: bool,
    #[allow(dead_code)]
    uv: bool,
}

#[derive(Debug, Serialize)]
struct MakeCredentialResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    _padding: Option<()>,
    fmt: String,
    auth_data: Bytes,
    att_stmt: std::collections::BTreeMap<i8, i8>,
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
    _padding: Option<()>,
    rp_id: String,
    client_data_hash: Bytes,
    #[serde(default)]
    allow_list: Vec<PublicKeyCredentialDescriptor>,
    #[allow(dead_code)]
    extensions: Option<()>,
    #[serde(default = "options_default")]
    #[allow(dead_code)]
    options: GetAssertionOptions,
}

#[derive(Debug, Deserialize, Default)]
struct GetAssertionOptions {
    #[serde(default = "up_default")]
    up: bool,
    #[serde(default)]
    #[allow(dead_code)]
    uv: bool,
}
fn options_default() -> GetAssertionOptions {
    GetAssertionOptions {
        up: true,
        uv: false,
    }
}
fn up_default() -> bool {
    options_default().up
}

#[derive(Debug, Serialize)]
struct GetAssertionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    _padding: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<PublicKeyCredentialDescriptor>,
    auth_data: Bytes,
    signature: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<User>,
    #[serde(skip_serializing_if = "Option::is_none")]
    number_of_credentials: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialId {
    pub wrapped_private_key: Bytes,
    pub encrypted_rp_id: Bytes,
}

impl Serialize for CoseKey {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
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

impl Serialize for PublicKeyCredentialDescriptor {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde_cbor::value::Value::*;
        let mut entries = vec![
            ("id", Bytes(self.id.0.clone())),
            ("type", Text(self.r#type.clone())),
        ];
        if self.transports.len() > 0 {
            let strings =
                self.transports.iter().map(|s| Text(s.clone())).collect();
            entries.insert(1, ("transports", Array(strings)));
            todo!()
        }
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for (k, v) in entries.iter() {
            map.serialize_entry(&Text(k.to_string()), v)?;
        }
        map.end()
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
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
    where
        E: serde::de::Error,
    {
        Ok(Bytes(v.to_vec()))
    }
}

pub const CTAP2_GET_INFO: u8 = 0x04;
const CTAP2_MAKE_CREDENTIAL: u8 = 0x01;
const CTAP2_GET_ASSERTION: u8 = 0x02;

pub const CTAP1_ERR_SUCCESS: u8 = 0x00;
const ERR_INVALID_CBOR: u8 = 0x12;
const ERR_OPERATION_DENIED: u8 = 0x27;
const ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
const ERR_INVALID_CREDENTIAL: u8 = 0x22;

const AAGUID: u128 = 0x7ec96c58403748ed8e7eb2a1b538374e;
//const AAGUID: u128 = 0x0;

pub fn process_request(req: Vec<u8>, f: GetConsent, t: Token) -> Vec<u8> {
    let (cmd, cbor) = (req[0], &req[1..]);
    log!("ctap2::process_request cmd: {:?}", cmd);
    let s = CTAP2 {
        get_consent: f,
        token: t,
    };
    let response = match cmd {
        CTAP2_GET_INFO => s.get_info(cbor),
        CTAP2_MAKE_CREDENTIAL => s.make_credential(cbor),
        CTAP2_GET_ASSERTION => s.get_assertion(cbor),
        _ => todo!(),
    }
    .map_or_else(
        |code| vec![code],
        |mut data| {
            data.insert(0, CTAP1_ERR_SUCCESS);
            data
        },
    );
    response
}

impl<'a> CTAP2<'a> {
    fn get_info(&self, cbor: &[u8]) -> C2R {
        log!("get_info");
        assert!(cbor.len() == 0);
        let reply = GetInfoResponse {
            _padding: None,
            versions: vec!["FIDO_2_0".to_owned(), "U2F_V2".to_owned()],
            aaguid: Bytes(AAGUID.to_le_bytes().to_vec()),
            extensions: Some(vec![]),
        };
        Ok(serde_cbor::ser::to_vec_packed(&reply).unwrap())
    }
    fn make_credential(&self, cbor: &[u8]) -> C2R {
        let args: MakeCredentialArgs = match serde_cbor::from_slice(cbor) {
            Ok(args) => args,
            Err(e) => {
                dbg!(e);
                return Err(ERR_INVALID_CBOR);
            }
        };
        log!("CTAP2_MAKE_CREDENTIAL {}", args.rp.id);
        if !args.user.id.0.len() <= 64 {
            todo!();
        }
        let algs = args.pub_key_algs;
        if !algs.iter().any(|a| a.alg == -7 && a.r#type == "public-key") {
            todo!()
        };
        let prompt = format!(
            "Consent needed for creating registration credentials

  Relying Party: {} ({:?})
  User: {:?} ({:?})

Allow? ",
            &args.rp.id,
            &args.rp.name,
            &args.user.name,
            &args.user.display_name
        );
        match (self.get_consent)(prompt) {
            Ok(false) => return Err(ERR_OPERATION_DENIED),
            Err(()) => {
                log!("ERR_KEEPALIVE_CANCEL");
                return Err(ERR_KEEPALIVE_CANCEL);
            }
            Ok(true) => (),
        }
        let (privk, pubk) = self.token.generate_key_pair().unwrap();
        assert!(!args.options.rk);
        let pub_key_cose = serde_cbor::ser::to_vec_packed(&CoseKey {
            kty: 2,
            alg: -7,
            crv: 1,
            x: Bytes(pubk.0),
            y: Bytes(pubk.1),
        })
        .unwrap();
        let auth_data = self.build_auth_data(
            args.rp.id.as_bytes(),
            &privk,
            &pub_key_cose,
        );
        let att_obj = MakeCredentialResponse {
            _padding: None,
            fmt: "none".to_string(),
            auth_data: Bytes(auth_data),
            att_stmt: std::collections::BTreeMap::new(),
        };
        Ok(serde_cbor::ser::to_vec_packed(&att_obj).unwrap())
    }

    fn build_auth_data(
        &self,
        rp_id: &[u8],
        wrapped_priv_key: &[u8],
        pub_key_cose: &[u8],
    ) -> Vec<u8> {
        let counter: u32 = self.token.increment_token_counter().unwrap();
        let flags: u8 = 1 << 0 | 1 << 6;
        let credential_id =
            serde_cbor::ser::to_vec_packed(&CredentialId {
                wrapped_private_key: Bytes(wrapped_priv_key.to_vec()),
                encrypted_rp_id: Bytes(
                    self.token.encrypt(&rp_id).unwrap(),
                ),
            })
            .unwrap();
        [
            &self.token.sha256_hash(rp_id).unwrap()[..],
            &[flags],
            &counter.to_be_bytes(),
            &AAGUID.to_le_bytes(),
            &(credential_id.len() as u16).to_be_bytes(),
            &credential_id,
            pub_key_cose,
        ]
        .concat()
    }

    fn get_assertion(&self, cbor: &[u8]) -> C2R {
        let args: GetAssertionArgs = match serde_cbor::from_slice(cbor) {
            Ok(x) => x,
            Err(e) => {
                log!("failed to parse cbor: {}", e);
                todo!() //return Err(ERR_INVALID_PAR);
            }
        };
        log!("get_assertion {:?}", args);
        if args.allow_list.len() != 1 {
            todo!()
        }
        let credential_id: CredentialId =
            match serde_cbor::from_slice(&args.allow_list[0].id.0) {
                Ok(x) => x,
                Err(_) => return Err(ERR_INVALID_CREDENTIAL),
            };
        match (
            self.token.decrypt(&credential_id.encrypted_rp_id.0),
            args.rp_id.as_bytes(),
        ) {
            (Ok(id1), id2) if id1 == id2 => (),
            _ => return Err(ERR_INVALID_CREDENTIAL),
        };
        let prompt = format!(
            "Consent needed for signing challenge

  Relying Party: {}

Allow?",
            &args.rp_id
        );
        match (self.get_consent)(prompt) {
            Ok(false) => return Err(ERR_OPERATION_DENIED),
            Err(()) => return Err(ERR_KEEPALIVE_CANCEL),
            Ok(true) => (),
        }
        let credential_id = serde_cbor::from_slice::<CredentialId>(
            &args.allow_list[0].id.0,
        )
        .unwrap();
        let wpriv_key = &credential_id.wrapped_private_key.0;
        let counter = self.token.increment_token_counter().unwrap();
        let auth_data: Vec<u8> = [
            &self.token.sha256_hash(args.rp_id.as_bytes()).unwrap()[..],
            &[
                1<<0| // User Present (UP) result
                0<<6, // Attested credential data included (AT).
            ],
            &counter.to_be_bytes(),
        ]
        .concat();
        let data = [&auth_data[..], &args.client_data_hash.0].concat();
        let signature = self.token.sign(wpriv_key, &data).unwrap();
        let response = GetAssertionResponse {
            _padding: None,
            auth_data: Bytes(auth_data),
            signature: Bytes(signature),
            credential: Some(args.allow_list[0].clone()),
            number_of_credentials: Some(1),
            user: None,
        };
        Ok(serde_cbor::ser::to_vec_packed(&response).unwrap())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    pub fn check_get_info_response(data: &[u8]) {
        assert_eq!(data[0], CTAP1_ERR_SUCCESS);
        let r: GetInfoResponse =
            serde_cbor::from_slice(&data[1..]).unwrap();
        let Bytes(aaguid) = r.aaguid;
        assert_eq!(aaguid, AAGUID.to_le_bytes());
        assert!(r.versions.iter().any(|v| v == "FIDO_2_0"));
        assert!(r.versions.iter().any(|v| v == "U2F_V2"));
    }
}
