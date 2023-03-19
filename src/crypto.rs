// Copyright: Helmut Eller
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::prompt;
use chrono::{DateTime, Utc};
use cryptoki::{
    context::Pkcs11,
    error::Result as CResult,
    mechanism::Mechanism as M,
    object::{
        Attribute as A, AttributeType, KeyType, ObjectClass, ObjectHandle,
    },
    session::Session,
    slot::Slot,
};
use secrecy::{zeroize::Zeroize, SecretString};
use std::convert::TryInto;
use std::error::Error;
use std::sync::{Mutex, MutexGuard};

type R<T> = Result<T, Box<dyn Error>>;

pub struct KeyStore<'a> {
    s: Session,
    #[allow(dead_code)]
    // guard.drop unlocks the global mutex
    guard: MutexGuard<'a, ()>,
}

// Realistically, at most one session can be open at any time.
static MUTEX: Mutex<()> = Mutex::new(());

pub fn open_token<'a>(
    module: &str,
    label: &str,
    pin_file: Option<&str>,
) -> R<KeyStore<'a>> {
    let guard = MUTEX.lock()?;
    let path = std::path::Path::new(module);
    let mut pkcs11 = Pkcs11::new(path)?;
    pkcs11.initialize(cryptoki::context::CInitializeArgs::OsThreads)?;
    let slot = match find_token(&pkcs11, label)?[..] {
        [slot] => slot,
        [] => Err("No token with matching label found")?,
        _ => Err("Multiple tokens with matching label found")?,
    };
    // Note: open_rw_session clones pkcs11.
    let s = login(&pkcs11, slot, pin_file.map(|x| x.as_ref()))?;
    let token = KeyStore::<'a> { guard: guard, s: s };
    match token.find_secret_key()? {
        None => {
            log!("Generating secret key...");
            token.create_secret_key()?
        }
        _ => log!("Found secret key."),
    };
    match token.find_token_counter()? {
        None => {
            log!("Generating token counter...");
            token.create_token_counter(0)?
        }
        _ => log!(
            "Found token counter. ({})",
            token.increment_token_counter()?
        ),
    };
    Ok(token)
}

fn find_token(pkcs11: &Pkcs11, label: &str) -> CResult<Vec<Slot>> {
    let mut result = vec![];
    for slot in pkcs11.get_slots_with_token()? {
        let info = pkcs11.get_token_info(slot)?;
        if label == info.label() {
            result.push(slot);
        }
    }
    Ok(result)
}

fn login(p: &Pkcs11, slot: Slot, pin_file: Option<&str>) -> R<Session> {
    let info = p.get_token_info(slot)?;
    let s = p.open_rw_session(slot)?;
    let need_pin = !info.protected_authentication_path();
    let pin = match (need_pin, pin_file) {
        (false, _) => SecretString::from("".to_string()),
        (true, None) => prompt::read_pin(&format!(
            "Please insert the User PIN for the token with\nlabel: {}",
            info.label()
        ))?,
        (true, Some(filename)) => read_pin_file(&filename)?,
    };
    s.login(cryptoki::session::UserType::User, need_pin.then(|| &pin))
        .map_err(|e| format!("login failed: {}", &e))?;
    Ok(s)
}

fn read_pin_file(file: &str) -> std::io::Result<SecretString> {
    let mut output = std::process::Command::new("gpg")
        .arg("--decrypt")
        .arg(file)
        .output()?;
    use std::io::{Error as E, ErrorKind};
    let r = if output.status.success() {
        let b = &output.stdout;
        std::str::from_utf8(&b[..b.len() - 1])
            .map(|s| SecretString::from(String::from(s)))
            .map_err(|e| E::new(ErrorKind::InvalidData, e))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = format!(
            "read_pin_file {} failed: gpg failed: {}",
            file, stderr
        );
        Err(E::new(ErrorKind::Other, msg))
    };
    output.stdout.zeroize();
    r
}

// OID: 1.2.840.10045.3.1.7
const OID_SECP256R1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];

fn curve_oid(name: &str) -> &'static [u8] {
    // DER encoding of OID: 1.2.840.10045.3.1.7
    const OID: &[u8] =
        &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    match name {
        "secp256r1" =>
        /*"1.2.840.10045.3.1.7".as_bytes() */
        {
            OID
        }
        _ => panic!("Uknown curve: {}", name),
    }
}

// fn der_encode_oid(oid: &'static [u64]) -> Vec<u8> {
//     let (buf, _pos) = cookie_factory::gen(
//         x509::der::write::der_oid(oid),
//         Vec::<u8>::new()).unwrap();
//     buf
// }

// See Section Octet-String-to-Elliptic-Curve-Point Conversion
// in http://www.secg.org/sec1-v2.pdf.
fn ec_point_x_y(point: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert!(point[0] == 0x04, "not a DER octed string tag");
    assert!(point[1] == 65, "invalid length");
    assert!(point[2] == 0x04, "point not in uncompressed format");
    let len = point.len();
    assert!(len == 67);
    assert!((len - 3) % 2 == 0);
    let l = (len - 3) / 2;
    assert!(l == 32);
    let (x, y) = (point[3..3 + l].to_vec(), point[3 + l..].to_vec());
    (x, y)
}

fn der_encode_signature(points: &[u8]) -> Vec<u8> {
    assert!(points.len() == 64);
    let (r, s) = (&points[..32], &points[32..]);
    fn encode_integer(mut int: &[u8], out: &mut Vec<u8>) {
        out.push(0x02);
        int = &int[int.iter().position(|&i| i != 0).unwrap()..];
        if int[0] & 0x80 != 0 {
            // would be interpreted as sign flag
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

const SECRET_KEY_LABEL: &str = "softfido-secret-key";
const TOKEN_COUNTER_LABEL: &str = "softfido-token-counter";

impl<'a> KeyStore<'a> {
    fn find_secret_key(&self) -> R<Option<ObjectHandle>> {
        let attrs = &vec![
            A::Label(SECRET_KEY_LABEL.into()),
            A::Class(ObjectClass::SECRET_KEY),
        ];
        let r = self
            .s
            .find_objects(attrs)
            .or_else(|e| Err(format!("find_objects failed: {}", &e)))?;
        match r.len() {
            0 => Ok(None),
            1 => Ok(Some(r[0])),
            _ => Err("Found multiple secret keys")?,
        }
    }

    fn find_token_counter(&self) -> R<Option<ObjectHandle>> {
        let attrs = vec![
            A::Label(TOKEN_COUNTER_LABEL.into()),
            A::Class(ObjectClass::DATA),
        ];
        match self.s.find_objects(&attrs)?[..] {
            [] => Ok(None),
            [c] => Ok(Some(c)),
            _ => Err("Found multiple token counters")?,
        }
    }

    fn create_secret_key(&self) -> CResult<()> {
        self.s.generate_key(
            &M::AesKeyGen,
            &vec![
                A::Class(ObjectClass::SECRET_KEY),
                A::KeyType(KeyType::AES),
                A::ValueLen(32.into()),
                A::Label(SECRET_KEY_LABEL.into()),
                A::Token(true),
                A::Sensitive(true),
                A::Extractable(false),
                A::Wrap(true),
                A::Unwrap(true),
                A::Encrypt(true),
                A::Decrypt(true),
            ],
        )?;
        assert!(self.find_secret_key().unwrap().is_some());
        Ok(())
    }

    fn create_token_counter(&self, value: u32) -> CResult<()> {
        self.s.create_object(&vec![
            A::Class(ObjectClass::DATA),
            A::Token(true),
            A::Label(TOKEN_COUNTER_LABEL.into()),
            A::Destroyable(true),
            A::Value(value.to_le_bytes()[..].to_vec()),
        ])?;
        assert!(self.find_token_counter().unwrap().is_some());
        Ok(())
    }

    pub fn increment_token_counter(&self) -> CResult<u32> {
        let counter = self.find_token_counter().unwrap().unwrap();
        let template = vec![AttributeType::Value];
        let attrs = self.s.get_attributes(counter, &template)?;
        let bytes = match &attrs[..] {
            [A::Value(bytes)] => bytes,
            _ => {
                panic!("bug in increment_token_counter: {:?}", &attrs)
            }
        };
        let v = u32::from_le_bytes(TryInto::try_into(&bytes[..])?);
        self.s.destroy_object(counter)?;
        self.create_token_counter(v + 1)?;
        Ok(v)
    }

    // Return the private and public keys.
    // The wrapped private key is also the credentialId.
    // The public key is an (x, y) point of an elliptic curve.
    pub fn generate_key_pair(&self) -> R<(Vec<u8>, (Vec<u8>, Vec<u8>))> {
        let pub_attrs = vec![
            A::KeyType(KeyType::EC),
            A::Token(false),
            A::EcParams(curve_oid("secp256r1").into()),
        ];
        let priv_attrs = &vec![A::Token(false), A::Extractable(true)];
        let (pub_key, priv_key) = self
            .s
            .generate_key_pair(&M::EccKeyPairGen, &pub_attrs, &priv_attrs)
            .map_err(|e| format!("generate_key_pair failed: {}", &e))?;
        let wrapping_key = self.find_secret_key()?.unwrap();
        let wrapped_key =
            self.s.wrap_key(&M::AesKeyWrapPad, wrapping_key, priv_key)?;
        let attrs =
            self.s.get_attributes(pub_key, &[AttributeType::EcPoint])?;
        let pub_x_y = match &attrs[..] {
            [A::EcPoint(point)] => ec_point_x_y(&point),
            _ => panic!("bug in generate_key_pair: {:?}", &attrs),
        };
        Ok((wrapped_key, pub_x_y))
    }

    pub fn is_valid_id(&self, key: &[u8]) -> bool {
        let wrapping_key = self.find_secret_key().unwrap().unwrap();
        let template = vec![
            A::Class(ObjectClass::PRIVATE_KEY),
            A::KeyType(KeyType::EC),
            A::Token(false),
        ];
        self.s
            .unwrap_key(&M::AesKeyWrapPad, wrapping_key, &key, &template)
            .is_ok()
    }

    pub fn sha256_hash(&self, data: &[u8]) -> CResult<Vec<u8>> {
        self.s.digest(&M::Sha256, &data)
    }

    pub fn sign(&self, key: &[u8], data: &[u8]) -> R<Vec<u8>> {
        let wrapping_key = self.find_secret_key()?.unwrap();
        let attrs = vec![
            A::Class(ObjectClass::PRIVATE_KEY),
            A::KeyType(KeyType::EC),
            A::Token(false),
        ];
        let private_key = self
            .s
            .unwrap_key(&M::AesKeyWrapPad, wrapping_key, key, &attrs)
            .map_err(|e| format!("unwrap_key failed: {}", &e))?;
        let hash = self.sha256_hash(&data)?;
        let signature = self.s.sign(&M::Ecdsa, private_key, &hash[..])?;
        Ok(der_encode_signature(&signature))
    }

    pub fn encrypt(&self, data: &[u8]) -> R<Vec<u8>> {
        println!("encrypt: data.len={}", data.len());
        let len = data.len();
        assert!(len <= 255);
        let d =
            [&[len as u8][..], data, &vec![0u8; 31 - len % 32]].concat();
        let key = self.find_secret_key()?.unwrap();
        Ok(self.s.encrypt(&M::AesEcb, key, &d)?)
    }

    pub fn decrypt(&self, data: &[u8]) -> R<Vec<u8>> {
        println!("decrypt");
        if data.len() % 32 != 0 || data.len() == 0 {
            Err("data has invalid length")?
        }
        let key = self.find_secret_key()?.unwrap();
        let d = self.s.decrypt(&M::AesEcb, key, data)?;
        let len = d[0];
        if 1 + len as usize > d.len() {
            Err("invalid decrypted data")?
        }
        Ok(d[1..1 + len as usize].to_vec())
    }

    // FIXME: use clock from token
    pub fn create_certificate(
        &self,
        wrapped_priv_key: &[u8],
        pub_key: &[u8],
        issuer: &str,
        subject: &str,
        not_before: DateTime<Utc>,
        not_after: Option<DateTime<Utc>>,
    ) -> R<Vec<u8>> {
        let sig_algo = EcdsaWithSha256 {};
        let (tbs_cert, _pos) = cookie_factory::gen(
            x509::write::tbs_certificate(
                &[0],
                &sig_algo,
                issuer,
                not_before,
                not_after,
                subject,
                &EcSubjectPublicKeyInfo {
                    public_key: pub_key,
                },
            ),
            Vec::<u8>::new(),
        )?;
        let sig = self.sign(wrapped_priv_key, &tbs_cert)?;
        let (cert, _pos) = cookie_factory::gen(
            x509::write::certificate(&tbs_cert, &sig_algo, &sig),
            Vec::new(),
        )?;
        Ok(cert)
    }
}

#[derive(Clone)]
struct EcPublicKey {}
#[derive(Clone)]
struct EcdsaWithSha256 {}

impl x509::AlgorithmIdentifier for EcdsaWithSha256 {
    type AlgorithmOid = &'static [u64];
    fn algorithm(&self) -> &'static [u64] {
        OID_ECDSA_WITH_SHA256
    }
    fn parameters<W: std::io::Write>(
        &self,
        w: cookie_factory::WriteContext<W>,
    ) -> cookie_factory::GenResult<W> {
        Ok(w)
    }
}

impl x509::AlgorithmIdentifier for EcPublicKey {
    type AlgorithmOid = &'static [u64];
    fn algorithm(&self) -> &'static [u64] {
        OID_EC_PUBLIC_KEY
    }
    fn parameters<W: std::io::Write>(
        &self,
        w: cookie_factory::WriteContext<W>,
    ) -> cookie_factory::GenResult<W> {
        x509::der::write::der_oid(OID_SECP256R1)(w)
    }
}

struct EcSubjectPublicKeyInfo<'a> {
    public_key: &'a [u8],
}

impl<'a> x509::SubjectPublicKeyInfo for EcSubjectPublicKeyInfo<'a> {
    type AlgorithmId = EcPublicKey;
    type SubjectPublicKey = &'a [u8];
    fn algorithm_id(&self) -> Self::AlgorithmId {
        EcPublicKey {}
    }
    fn public_key(&self) -> &'a [u8] {
        self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::R;

    fn get_token<'a>() -> R<super::KeyStore<'a>> {
        let lib = "/usr/lib/softhsm/libsofthsm2.so";
        let home = std::env::var("HOME")?;
        let pinfile =
            format!("{}/.password-store/softhsm2/user-pin.gpg", home);
        let label = "softfido";
        super::open_token(lib, label, Some(pinfile.as_ref()))
    }

    #[test]
    fn open_token() -> R<()> {
        get_token()?;
        get_token()?;
        get_token()?;
        Ok(())
    }

    #[test]
    // this is run in another thread
    fn open_token2() -> R<()> {
        get_token()?;
        get_token()?;
        get_token()?;
        Ok(())
    }

    #[test]
    fn get_keys() -> R<()> {
        let token = get_token()?;
        token.generate_key_pair()?;
        Ok(())
    }

    #[test]
    fn print_cert() -> R<()> {
        let token = get_token()?;
        let (wpriv_key, (x, y)) = token.generate_key_pair()?;
        let pub_key = [&[4u8][..], &x[..], &y].concat();
        let not_before = chrono::Utc::now();
        let not_after = not_before + chrono::Duration::days(30);
        let cert = token.create_certificate(
            &wpriv_key,
            &pub_key,
            "Fakecompany",
            "Fakecompany",
            not_before,
            Some(not_after),
        )?;
        let mut file = std::fs::File::create("/tmp/cert.der")?;
        use std::io::Write;
        file.write_all(&cert[..])?;
        Ok(())
    }
}
