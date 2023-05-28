use crate::crypto::Token;
use crate::ctap2;
use crate::hex::hex;
use ctap2::GetConsent;

struct U2F<'a> {
    get_consent: GetConsent<'a>,
    token: &'a Token,
}

type U2R = Result<Vec<u8>, u16>;

const SW_NO_ERROR: u16 = 0x9000;
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
//const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
const SW_WRONG_DATA: u16 = 0x6A80;

pub fn process_request(req: Vec<u8>, f: GetConsent, t: &Token) -> Vec<u8> {
    let s = U2F {
        get_consent: f,
        token: t,
    };
    fn payload(data: &[u8]) -> &[u8] {
        // extended length encoding of request length.
        match data {
            [0, n2, n1, rest @ ..] => {
                let nc = u16::from_be_bytes([*n2, *n1]) as usize;
                let request_data = &rest[..nc];
                request_data
            }
            _ => &[],
        }
    }
    let result = match (&req[..4], payload(&req[4..])) {
        ([0, 3, 0, 0], []) => s.u2f_version(),
        ([0, 1, 0, 0], params) => s.u2f_register(params),
        ([0, 2, p1 @ (3 | 7 | 8), 0], args) => {
            s.u2f_authenticate(*p1, args)
        }
        // not spec compliant, but Chrome sends this
        ([0, 1, 3, 0], params) => s.u2f_register(params),
        (req, payload) => {
            dbg!(req, payload);
            eprintln!("req: {:x?}", req);
            todo!()
        }
    };
    match result {
        Ok(mut v) => {
            v.extend(SW_NO_ERROR.to_be_bytes());
            v
        }
        Err(code) => code.to_be_bytes().to_vec(),
    }
}

impl<'a> U2F<'a> {
    fn u2f_version(&self) -> U2R {
        Ok(b"U2F_V2".to_vec())
    }

    fn u2f_register(&self, data: &[u8]) -> U2R {
        log!(CTAP, "u2f_register: {:?}", &data);
        assert!(data.len() == 64);
        let challenge = &data[..32];
        let application = &data[32..];
        let query = format!(
            "Allow U2F registeration?

challenge: {}
application: {}
",
            hex(challenge),
            hex(application)
        );
        if let Ok(false) | Err(()) = (self.get_consent)(query) {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }
        log!(CRYPTO, "generate_key_pair");
        let (wpriv, (x, y)) = self.token.generate_key_pair().unwrap();
        let pub_key = [&[4u8][..], &x, &y].concat();
        assert!(pub_key.len() == 65);
        assert!(wpriv.len() <= 255);
        log!(CRYPTO, "encrypt rp_id");
        let credential_id = ctap2::CredentialId {
            wrapped_private_key: ctap2::Bytes(wpriv.clone()),
            encrypted_rp_id: ctap2::Bytes(
                self.token.encrypt(&application).unwrap(),
            ),
        };
        println!("credential_id: {:?}", &credential_id);
        println!("application: {:?}", &application);
        let key_handle =
            serde_cbor::ser::to_vec_packed(&credential_id).unwrap();
        log!(CRYPTO, "sign");
        let signature = self
            .token
            .sign(
                &wpriv,
                &[
                    &[0u8][..],
                    application,
                    challenge,
                    &key_handle,
                    &pub_key,
                ]
                .concat(),
            )
            .unwrap();
        let not_before = chrono::Utc::now();
        let not_after = not_before + chrono::Duration::days(30);
        log!(CRYPTO, "create_certificate");
        let cert = self
            .token
            .create_certificate(
                &wpriv,
                &pub_key,
                "Fakecompany",
                "Fakecompany",
                not_before,
                Some(not_after),
            )
            .unwrap();
        assert!(key_handle.len() <= 255);
        Ok([
            &[5u8][..], // reserved byte 5
            &pub_key,
            &[key_handle.len() as u8],
            &key_handle,
            &cert,
            &signature,
        ]
        .concat())
    }

    fn u2f_authenticate(&self, control: u8, data: &[u8]) -> U2R {
        log!(CTAP, "u2f_authenticate: 0x{:0x} {:?}", control, &data);
        let challange = &data[..32];
        let application = &data[32..64];
        let l = data[64];
        let key_handle = &data[65..];
        assert!(key_handle.len() == l as usize);
        let credential_id: ctap2::CredentialId =
            match serde_cbor::from_slice(key_handle) {
                Ok(x) => x,
                _ => return Err(SW_WRONG_DATA),
            };
        println!("credential_id = {:?}", &credential_id);
        println!("application: {:?}", &application);
        let wpriv = &credential_id.wrapped_private_key.0;
        assert!(self.token.is_valid_id(wpriv));
        match self.token.decrypt(&credential_id.encrypted_rp_id.0) {
            Ok(rp_id) if rp_id == application => (),
            _ => return Err(SW_WRONG_DATA),
        };
        match control {
            7 => Err(SW_CONDITIONS_NOT_SATISFIED),
            3 => {
                let query = "Allow U2F authentication?".into();
                if let Ok(false) | Err(()) = (self.get_consent)(query) {
                    return Err(SW_CONDITIONS_NOT_SATISFIED);
                }
                let presence = 1u8;
                let token = &self.token;
                let counter = token.increment_token_counter().unwrap();
                let sig = token
                    .sign(
                        wpriv,
                        &[
                            application,
                            &[presence],
                            &counter.to_be_bytes(),
                            challange,
                        ]
                        .concat(),
                    )
                    .unwrap();
                Ok([&[presence][..], &counter.to_be_bytes(), &sig]
                    .concat())
            }
            _ => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn registration() {
        ()
    }
}
