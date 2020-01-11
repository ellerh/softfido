

#import fido2
## .hid import CtapHidDevice
import fido2
from fido2.hid import CtapHidDevice
from fido2._pyu2f import hidtransport
from fido2 import ctap2
from fido2.cose import ES256
from binascii import a2b_hex

# dev = hid.Open( '/dev/hidraw24')
# hidtransport.UsbHidTransport(dev)

def test_enum_hid (): return list(hidtransport.hid.Enumerate())
#dev = fido2._pyu2f.hidtransport.hid.Open( '/dev/hidraw1')

def test_open ():
    devnames = test_enum_hid()
    return hidtransport.hid.Open(devnames[0]['path'])

def test_list_devices (): return list(CtapHidDevice.list_devices())

def open_ctaphid_device():
    for d in CtapHidDevice.list_devices():
        return d
    raise Exception("Can't open ctaphid device")

def test_ping(): return open_ctaphid_device().ping()
def open_ctap(): return ctap2.CTAP2(open_ctaphid_device())
def test_get_info(): return open_ctap().get_info()

rp = {'id': 'example.com', 'name': 'Example RP'}
user = {'id': b'user_id',
        'displayName': 'auser@example.com',
        'name': "A. User" }
algos=[ES256.ALGORITHM]
key_params = [{'type': 'public-key', 'alg': alg} for alg in algos]

def test_make_credential():
    def on_keepalive (status):
        print("on_keepalive: ", status)
    return open_ctap().make_credential(b'hash', rp, user, key_params,
                                       on_keepalive=on_keepalive)

def test_timeout():
    return open_ctap().make_credential(b'hash',
                                       {'id': "timeout.com",
                                        'name': "Please don't confirm"},
                                       user, key_params,
                                       timeout=0.1)

def test_failed_assertion():
    client_data_hash = a2b_hex(
        "7e9bb3719fd1b56e4f6c66b4b241b7fc3ede9b10629684dc6c1a710c166746e4")
    credential_id = a2b_hex(
        "4a1749b168565d2d0e1cb2f8c200cbc7e53e9957c75d89ba3db761cc0d7e5181")
    return open_ctap().get_assertion("webauthn.io",
                                     client_data_hash,
                                     [{"type": "public-key",
                                       "id": credential_id}],
                                     None,
                                     {"up": False})

from fido2 import server
from fido2 import attestation
from fido2 import client
from fido2.utils import websafe_encode

def make_server():
    return server.Fido2Server(server.RelyingParty("foo.com", "foosite"),
                              attestation_types=attestation.NoneAttestation())

def test_register_and_authenticate():
    s = make_server()
    user = {"id": b'"user-id"', "name": "username",
            "displayName": "displayName"}
    (args, state) = s.register_begin(user)
    c = client.Fido2Client(open_ctaphid_device(), "https://foo.com")
    challenge = websafe_encode(args["publicKey"]["challenge"])
    (att, client_data) = c.make_credential(args["publicKey"]["rp"],
                                           user, challenge)
    auth_data = s.register_complete(state, client_data, att)
    (args, state) = s.authenticate_begin([auth_data.credential_data])
    challenge = websafe_encode(args["publicKey"]["challenge"])
    ([a], client_data) = c.get_assertion(
        args["publicKey"]["rpId"],
        challenge,
        [{"type": "public-key",
          "id": auth_data.credential_data.credential_id}],)
    return s.authenticate_complete(state,[auth_data.credential_data],
                                   auth_data.credential_data.credential_id,
                                   client_data, a.auth_data, a.signature)

def test_tampered_rp_id():
    user = {'id': b'user_id',
            'displayName': 'auser@example.com',
            'name': "A. User" }
    rp = {'id': "foo.com", 'name': "Tamper rpId"}
    dev = open_ctap()
    cred = dev.make_credential(b'hash', rp, user, key_params)
    challenge = b'Y2hhbGxlbmdl'
    tampered_rp_id = rp["id"] + "!"
    dev.get_assertion(
        tampered_rp_id,
        challenge,
        [{"type": "public-key",
          "id": cred.auth_data.credential_data.credential_id}],)

def open_ctap1 (): return fido2.ctap1.CTAP1(open_ctaphid_device())

#
import unittest
import threading

class Tests(unittest.TestCase):

    def test_enum_hid(self):
        self.assertTrue(len(test_enum_hid()) > 0)

    def test_list_devices(self):
        self.assertTrue(len(test_list_devices()) > 0)

    def test_ping(self):
        self.assertEqual(test_ping(), b'Hello FIDO')

    def test_info(self):
        self.assertIsInstance(test_get_info(), ctap2.Info)

    def test_info_versions(self):
        self.assertEqual(test_get_info().versions, ['FIDO_2_0', 'U2F_V2'])

    def test_make_credential(self):
        self.assertIsInstance(test_make_credential(), ctap2.AttestationObject)

    def test_timeout(self):
        try:
            test_timeout()
        except Exception as e:
            self.assertIsInstance(e, fido2.ctap.CtapError)
            self.assertEqual(e.code,
                             fido2.ctap.CtapError.ERR.INVALID_COMMAND)

    def test_failed_assertion (self):
        try:
            test_failed_assertion()
        except Exception as e:
            self.assertIsInstance(e, fido2.ctap.CtapError)
            self.assertEqual(e.code,
                             fido2.ctap.CtapError.ERR.INVALID_CREDENTIAL)
        else:
            self.assertTrue(False)

    def test_register_and_authenticate(self):
        self.assertIsInstance(test_register_and_authenticate(),
                              fido2.ctap2.AttestedCredentialData)

    def test_tampered_rp_id(self):
        try:
            test_tampered_rp_id()
        except Exception as e:
            self.assertIsInstance(e, fido2.ctap.CtapError)
            self.assertEqual(e.code,
                             fido2.ctap.CtapError.ERR.INVALID_CREDENTIAL)
        else:
            self.assertTrue(False)

    def test_open_ctap1(self):
        self.assertIsInstance(open_ctap1(), fido2.ctap1.CTAP1)

    def test_u2f_version(self):
        self.assertEqual(open_ctap1().get_version(), 'U2F_V2')

    def test_u2f_register(self):
        sha256 = fido2.utils.sha256
        clientdata = sha256(b'AAA')
        appid = sha256(b'BBB')
        regdata = open_ctap1().register(clientdata, appid)
        self.assertIsInstance(regdata, fido2.ctap1.RegistrationData)
        regdata.verify(appid, clientdata)

    def test_u2f_authenticate(self):
        sha256 = fido2.utils.sha256
        clientdata = sha256(b'AAA')
        appid = sha256(b'BBB')
        ctap1 = open_ctap1()
        regdata = ctap1.register(clientdata, appid)
        self.assertIsInstance(regdata, fido2.ctap1.RegistrationData)
        regdata.verify(appid, clientdata)
        auth = ctap1.authenticate(clientdata, appid, regdata.key_handle)
        self.assertIsInstance(auth, fido2.ctap1.SignatureData)
        auth.verify(appid, clientdata, regdata.public_key)

    def test_u2f_counter(self):
        sha256 = fido2.utils.sha256
        clientdata = sha256(b'AAA')
        appid = sha256(b'BBB')
        ctap1 = open_ctap1()
        regdata = ctap1.register(clientdata, appid)
        self.assertIsInstance(regdata, fido2.ctap1.RegistrationData)
        regdata.verify(appid, clientdata)
        auth1 = ctap1.authenticate(clientdata, appid, regdata.key_handle)
        self.assertIsInstance(auth1, fido2.ctap1.SignatureData)
        auth1.verify(appid, clientdata, regdata.public_key)
        auth2 = ctap1.authenticate(clientdata, appid, regdata.key_handle)
        self.assertIsInstance(auth1, fido2.ctap1.SignatureData)
        auth2.verify(appid, clientdata, regdata.public_key)
        self.assertTrue(auth1.counter < auth2.counter)

    def test_counter(self):
        dev = open_ctaphid_device()
        client = fido2.client.Fido2Client(dev, "https://example.com")
        rp = {'id': 'example.com', 'name': 'Example RP'}
        user = {'id': b'user_id', 'name': 'A. User'}
        pin = None
        challenge1 = 'Y2hhbGxlbmdl'
        attestation_object, client_data = client.make_credential(
            rp, user, challenge1, pin=pin)
        verifier = fido2.attestation.Attestation.for_type(
            attestation_object.fmt)
        verifier().verify(attestation_object.att_statement,
                          attestation_object.auth_data,
                          client_data.hash)
        credential = attestation_object.auth_data.credential_data
        challenge2 = 'Q0hBTExFTkdF'  # Use a new challenge for each call.
        allow_list = [{
            'type': 'public-key',
            'id': credential.credential_id
        }]
        assertions1, client_data1 = client.get_assertion(
            rp['id'], challenge2, allow_list, pin=pin)
        assertion1 = assertions1[0]
        assertion1.verify(client_data1.hash, credential.public_key)
        challenge3 = 'yooT1AiB'  # Use a new challenge for each call.
        assertions2, client_data2 = client.get_assertion(
            rp['id'], challenge3, allow_list, pin=pin)
        assertion2 = assertions2[0]
        assertion2.verify(client_data2.hash, credential.public_key)
        self.assertTrue(assertion1.auth_data.counter
                        < assertion2.auth_data.counter)


    def test_multichannel(self):
        dev1 = open_ctaphid_device()
        dev2 = open_ctaphid_device()
        client2 = fido2.client.Fido2Client(dev2, "https://example2.com")
        client1 = fido2.client.Fido2Client(dev1, "https://example1.com")
        rp1 = {'id': 'example1.com', 'name': 'Example RP'}
        rp2 = {'id': 'example2.com', 'name': 'Example RP'}
        user = {'id': b'user_id', 'name': 'A. User'}
        pin = None
        challenge1 = 'Y2hhbGxlbmdl'
        results = [None, None]
        barrier = threading.Barrier(3, timeout=10)
        def make_credential(index, client, rp):
            try:
                results[index] = client.make_credential(
                    rp, user, challenge1, pin=pin)
            except Exception as e:
                results[index] = e
            barrier.wait()
        threading.Thread(target=make_credential,args=(0,client1,rp1)).start()
        threading.Thread(target=make_credential,args=(1,client2,rp2)).start()
        barrier.wait()
        for r in results:
            if isinstance(r, fido2.ctap.CtapError):
                self.assertEqual(r.code,
                                 fido2.ctap.CtapError.ERR.CHANNEL_BUSY)
            if isinstance(r, tuple):
                (attestation_object, client_data) = r
                verifier = fido2.attestation.Attestation.for_type(
                    attestation_object.fmt)
                verifier().verify(attestation_object.att_statement,
                                  attestation_object.auth_data,
                                  client_data.hash)

    def test_timeout_get_assertion (self):
        dev = open_ctaphid_device()
        client = fido2.client.Fido2Client(dev, "https://example.com")
        rp = {'id': 'example.com', 'name': 'Example RP'}
        user = {'id': b'user_id', 'name': 'A. User'}
        pin = None
        challenge1 = 'Y2hhbGxlbmdl'
        attestation_object, client_data = client.make_credential(
            rp, user, challenge1, pin=pin)
        verifier = fido2.attestation.Attestation.for_type(
            attestation_object.fmt)
        verifier().verify(attestation_object.att_statement,
                          attestation_object.auth_data,
                          client_data.hash)
        credential = attestation_object.auth_data.credential_data
        challenge2 = 'Q0hBTExFTkdF'  # Use a new challenge for each call.
        allow_list = [{
            'type': 'public-key',
            'id': credential.credential_id
        }]
        try:
            assertions1, client_data1 = client.get_assertion(
                rp['id'], challenge2, allow_list, pin=pin, timeout=0.1)
        except Exception as e:
            self.assertEqual(e.__context__.code,
                             fido2.ctap.CtapError.ERR.INVALID_COMMAND)

if __name__ == '__main__':
    unittest.main()
