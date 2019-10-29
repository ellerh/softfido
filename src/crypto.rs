
use pkcs11::{Ctx, errors::Error};
use pkcs11::types::*;
use crate::prompt;
    
pub struct KeyStore {
    ctx: Ctx,
    session: CK_SESSION_HANDLE,
}

impl Drop for KeyStore {
    fn drop(&mut self) {
        self.ctx.close_session(self.session).unwrap()
    }
}

fn match_label(pattern: &str, label: &[u8; 32]) -> bool {
    match std::str::from_utf8(label) {
        Ok(label) => label.trim() == pattern.trim(),
        Err(_) => false
    }
}

fn find_token(ctx: &Ctx, label: &str) -> Result<Vec<CK_SLOT_ID>, Error> {
    let mut result = vec!();
    for slot_id in ctx.get_slot_list(true)? {
        let info = ctx.get_token_info(slot_id)?;
        if match_label(label, &info.label) {
            result.push(slot_id);
        }
    }
    Ok(result)
}

fn login(ctx: &Ctx, slot_id: CK_SLOT_ID) -> Result<CK_SESSION_HANDLE, Error> {
    let info = ctx.get_token_info(slot_id)?;
    let s = ctx.open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             None, None)?;
    let need_pin = info.flags & CKF_PROTECTED_AUTHENTICATION_PATH == 0;
    let pin = if need_pin {
        let prompt = format!(
            "Please insert the User PIN for the token with\nlabel: {}",
            String::from_utf8_lossy(&info.label));
        prompt::read_pin(&prompt).expect("Can't read PIN")
    } else {
        secstr::SecStr::new(vec!())
    };
    ctx.login(s, CKU_USER, match need_pin {
        true => Some(std::str::from_utf8(pin.unsecure()).unwrap()),
        false => None
    })?;
    Ok(s)
}

pub fn open_token (module: &std::path::Path, label: &str)
                   -> Result<KeyStore, Error> {
    let ctx = Ctx::new_and_initialize(module)?;
    let slot_ids = find_token(&ctx, label)?;
    let slot_id = match slot_ids.len() {
        1 => slot_ids[0],
        l => return Err(Error::Module(match l {
            0 => "No token with matching label found",
            _ => "Multiple tokens with matching label found",
        })),
    };
    let s = login(&ctx, slot_id)?;
    let token = KeyStore{ ctx: ctx, session: s};
    match token.find_secret_key()? {
        None => {
            log!("Generating secret key...");
            token.create_secret_key()?
        },
        _ => log!("Found secret key."),
    };
    Ok(token)
}

fn curve_oid (name: &str) -> &'static [u8] {
    // DER encoding of OID: 1.2.840.10045.3.1.7
    const OID:&[u8] =
        &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    match name {
        "secp256r1" => /*"1.2.840.10045.3.1.7".as_bytes() */ OID,
        _ => panic!("Uknown curve: {}", name)
    }
}

// See Section Octet-String-to-Elliptic-Curve-Point Conversion
// in http://www.secg.org/sec1-v2.pdf.
fn ec_point_x_y (point: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert!(point[0] == 0x04, "not a DER octed string tag");
    assert!(point[1] == 65, "invalid length");
    assert!(point[2] == 0x04, "point not in uncompressed format");
    let len = point.len();
    assert!(len == 67);
    assert!((len - 3) % 2 == 0);
    let l = (len - 3) / 2;
    assert!(l == 32);
    let (x, y) = (point[3..3+l].to_vec(), point[3+l..].to_vec());
    (x, y)
}

// Set all elements to 0
fn zero(data: &mut [u8]) {
    for i in 0..data.len() {
        data[i] = 0;
    }
}

fn with_vec<T, F>(data: &[u8], f: F) -> T
    where F: FnOnce(&Vec<u8>) -> T {
    let mut tmp = data.to_vec();
    let result = f(&tmp);
    zero(&mut tmp);
    result
}

fn der_encode_signature (points: &[u8]) -> Vec<u8> {
    assert!(points.len() == 64);
    let (r, s) = (&points[..32], &points[32..]);
    fn encode_integer (mut int: &[u8], out: &mut Vec<u8>) {
        out.push(0x02);
        int = &int[int.iter().position(|&i| i != 0).unwrap() ..];
        if int[0] & 0x80 != 0 {   // would be interpreted as sign flag
            out.push(int.len() as u8 + 1); // so insert an extra zero
            out.push(0);
        } else {
            out.push(int.len() as u8);
        };
        out.extend_from_slice(int)
    }
    let mut out = vec![0x30u8, 0];
    encode_integer(r, &mut out);
    encode_integer(s, &mut out);
    out[1] = out.len() as u8 - 2;
    out
}

pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = rust_crypto::sha2::Sha256::new();
    use crate::rust_crypto::digest::Digest;
    hasher.input(data);
    let mut result = vec!(0; hasher.output_bytes());
    hasher.result(&mut result);
    result
}

// shorthand for mechanism without paramaters.
fn mechanism(mechanism: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: mechanism,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    }
}

const A: fn(CK_ATTRIBUTE_TYPE) -> CK_ATTRIBUTE = CK_ATTRIBUTE::new;

const SECRET_KEY_LABEL: &str = "softfido-secret-key";

impl KeyStore {

    fn find_secret_key(&self) -> Result<Option<CK_OBJECT_HANDLE>, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        ctx.find_objects_init(
            s,
            &vec![A(CKA_LABEL).with_string(&SECRET_KEY_LABEL.to_string()),
                  A(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY)],)?;
        let r = ctx.find_objects(s, 2)?;
        ctx.find_objects_final(s)?;
        match r.len() {
            0 => Ok(None),
            1 => Ok(Some(r[0])),
            _ => Err(Error::Module("Found multiple secret keys"))
        }
    }

    fn create_secret_key(&self) -> Result<(), Error> {
        self.ctx.generate_key(
            self.session, &mechanism(CKM_AES_KEY_GEN),
            &vec![A(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY),
                  A(CKA_KEY_TYPE).with_ck_ulong(&CKK_AES),
                  A(CKA_VALUE_LEN).with_ck_ulong(&32),
                  A(CKA_LABEL).with_string(&SECRET_KEY_LABEL.to_string()),
                  A(CKA_TOKEN).with_bool(&CK_TRUE),
                  A(CKA_SENSITIVE).with_bool(&CK_TRUE),
                  A(CKA_EXTRACTABLE).with_bool(&CK_FALSE),
                  A(CKA_WRAP).with_bool(&CK_TRUE),
                  A(CKA_UNWRAP).with_bool(&CK_TRUE),
            ],)?;
        assert!(self.find_secret_key().unwrap().is_some());
        Ok(())
    }

    fn get_bytes_attribute(&self, key: CK_OBJECT_HANDLE,
                           attr: CK_ATTRIBUTE_TYPE)
                           -> Result<Vec<u8>, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        let mut template = vec![CK_ATTRIBUTE::new(attr)];
        match ctx.get_attribute_value(s, key, &mut template) {
            Ok((CKR_OK, _)) => (),
            Ok((CKR_BUFFER_TOO_SMALL, _)) => (),
            Ok((err,_)) => return Err(Error::Pkcs11(err)),
            Err(err) => return Err(err),
        }
        let mut bytes = vec!(0; template[0].ulValueLen);
        template[0].set_bytes(&mut bytes);
        match ctx.get_attribute_value(s, key, &mut template) {
            Ok((CKR_OK, _)) => Ok(bytes),
            Ok((err,_)) => Err(Error::Pkcs11(err)),
            Err(err) => Err(err),
        }
    }

    // Return the private and public keys.
    // The wrapped private key is also the credentialId.
    // The public key is an (x, y) point of an elliptic curve.
    pub fn generate_key_pair(&self) -> Result<(Vec<u8>, (Vec<u8>, Vec<u8>)),
                                              Error> {
        let (ctx, s) = (&self.ctx, self.session);
        let (pub_key, priv_key) = ctx.generate_key_pair(
            s, &mechanism(CKM_EC_KEY_PAIR_GEN),
            &vec![A(CKA_KEY_TYPE).with_ck_ulong(&CKK_EC),
                  A(CKA_TOKEN).with_bool(&CK_FALSE),
                  A(CKA_EC_PARAMS).with_bytes(curve_oid("secp256r1")),
            ],
            &vec![A(CKA_TOKEN).with_bool(&CK_FALSE),
                  A(CKA_EXTRACTABLE).with_bool(&CK_TRUE),
            ])?;
        let wrapping_key = self.find_secret_key()?.unwrap();
        let wrapped_key = ctx.wrap_key(s, &mechanism(CKM_AES_KEY_WRAP_PAD),
                                       wrapping_key, priv_key)?;
        Ok((wrapped_key,
            ec_point_x_y(&self.get_bytes_attribute(pub_key, CKA_EC_POINT)?)))
    }

    pub fn is_valid_id(&self, key: &[u8]) -> bool {
        let wrapping_key = self.find_secret_key().unwrap().unwrap();
        self.ctx.unwrap_key(
            self.session, &mechanism(CKM_AES_KEY_WRAP_PAD),
            wrapping_key, &key.to_vec(),
            &vec![A(CKA_CLASS).with_ck_ulong(&CKO_PRIVATE_KEY),
                  A(CKA_KEY_TYPE).with_ck_ulong(&CKK_EC),
                  A(CKA_TOKEN).with_bool(&CK_FALSE),
            ]).is_ok()
    }

    pub fn sha256_hash(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        ctx.digest_init(s, &mechanism(CKM_SHA256))?;
        with_vec(data, |data| ctx.digest(s, data))
    }
    
    pub fn sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        let (ctx, s) = (&self.ctx, self.session);
        let hash = self.sha256_hash(&data)?;
        assert!(hash == sha256_hash(data));
        let wrapping_key = self.find_secret_key()?.unwrap();
        let private_key = ctx.unwrap_key(
            s, &mechanism(CKM_AES_KEY_WRAP_PAD),
            wrapping_key, &key.to_vec(),
            &vec![A(CKA_CLASS).with_ck_ulong(&CKO_PRIVATE_KEY),
                  A(CKA_KEY_TYPE).with_ck_ulong(&CKK_EC),
                  A(CKA_TOKEN).with_bool(&CK_FALSE),
            ])?;
        ctx.sign_init(s, &mechanism(CKM_ECDSA), private_key)?;
        let signature = ctx.sign(s, &hash)?;
        Ok(der_encode_signature(&signature))
    }
}
