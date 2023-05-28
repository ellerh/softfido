#  Copyright: Helmut Eller
#  SPDX-License-Identifier: GPL-3.0-or-later

import fido2
import fido2.features
fido2.features.webauthn_json_mapping.enabled = False

from fido2.hid import CtapHidDevice
from fido2 import ctap2
from fido2.cose import ES256
from binascii import a2b_hex
from fido2 import server
from fido2 import attestation
from fido2 import client
from fido2.utils import websafe_encode, websafe_decode, sha256
import pprint
import time
import unittest
import threading

def test_open ():
    devnames = test_enum_hid()
    return hidtransport.hid.Open(devnames[0]['path'])

def test_list_devices (): return list(CtapHidDevice.list_devices())

def open_ctaphid_device():
    for d in CtapHidDevice.list_devices():
        return d
    raise Exception("Can't open ctaphid device")

def test_ping(): return open_ctaphid_device().ping()
def open_ctap(): return ctap2.Ctap2(open_ctaphid_device())
def test_get_info(): return open_ctap().get_info()

rp = {'id': 'example.com', 'name': 'Example RP'}
user = {'id': b'user_id',
        'displayName': 'auser@example.com',
        'name': "A. User" }
algos=[ES256.ALGORITHM]
key_params = [{'type': 'public-key', 'alg': alg} for alg in algos]

def test_make_credential():
    def on_keepalive (status):
        #print("on_keepalive: ", status)
        pass
    return open_ctap().make_credential(b'hash', rp, user, key_params,
                                       on_keepalive=on_keepalive)

def test_timeout(timeout, label):
    event = threading.Event()
    threading.Timer(timeout, event.set).start()
    def on_keepalive (status):
        #print("on_keepalive: ", status)
        pass
    return open_ctap().make_credential(b'hash',
                                       {'id': label,
                                        'name': "Please don't confirm"},
                                       user, key_params,
                                       on_keepalive=on_keepalive,
                                       event=event
                                       )

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

def make_server():
    attestation = fido2.attestation.NoneAttestation()
    return fido2.server.Fido2Server({"id": "foo.com", "name": "foosite"},
                                    attestation=attestation)

def test_register_and_authenticate():
    s = make_server()
    user = {"id": b'user-reg-id',
            "name": "username",
            "displayName": "displayName"}
    (create_options, state) = s.register_begin(user)
    c = client.Fido2Client(open_ctaphid_device(), "https://foo.com")
    pub_key=create_options["publicKey"]
    result = c.make_credential(pub_key)
    auth_data = s.register_complete(state, result.client_data,
                                    result.attestation_object)
    credentials = [auth_data.credential_data]
    (aoptions, state) = s.authenticate_begin(credentials)
    rs = c.get_assertion(aoptions["publicKey"])
    r = rs.get_response(0)
    return s.authenticate_complete(state,credentials,
                                   r.credential_id,
                                   r.client_data,
                                   r.authenticator_data,
                                   r.signature)

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

def open_ctap1 (): return fido2.ctap1.Ctap1(open_ctaphid_device())

class Tests(unittest.TestCase):


    def test_list_devices(self):
        self.assertTrue(len(test_list_devices()) > 0)

    def test_ping(self):
        self.assertEqual(test_ping(), b'Hello FIDO')

    def test_info(self):
        self.assertIsInstance(test_get_info(), ctap2.Info)

    def test_info_versions(self):
        self.assertEqual(test_get_info().versions, ['FIDO_2_0', 'U2F_V2'])

    def test_make_credential(self):
        cred = test_make_credential()
        self.assertIsInstance(cred, ctap2.AttestationResponse)

    def test_timeout(self):
        try:
            test_timeout(0.02, "timeout.com")
        except Exception as e:
            self.assertIsInstance(e, fido2.ctap.CtapError)
            self.assertEqual(e.code,
                             fido2.ctap.CtapError.ERR.KEEPALIVE_CANCEL)
            for i in range(3):
                time.sleep(0.1)
                self.test_ping()
        else:
            self.assertTrue(False)

    def test_timeout2(self):
        try:
            test_timeout(0.02, "timeout.com")
        except Exception as e:
            self.assertIsInstance(e, fido2.ctap.CtapError)
            self.assertEqual(e.code,
                             fido2.ctap.CtapError.ERR.KEEPALIVE_CANCEL)
            try:
                test_timeout(0.3, "timeout2.com")
            except Exception as e:
                self.assertIsInstance(e, fido2.ctap.CtapError)
                self.assertEqual(e.code,
                                 fido2.ctap.CtapError.ERR.KEEPALIVE_CANCEL)
            for i in range(3):
                time.sleep(0.1)
                self.test_ping()
        else:
            self.assertTrue(False)


    def test_deny_credentials(self):
        rp = {'id': "test-deny-credentials",
              'name': "Please deny your consent"}
        try:
            open_ctap().make_credential(b'hash', rp, user, key_params)
        except Exception as e:
            self.assertIsInstance(e, fido2.ctap.CtapError)
            self.assertEqual(e.code,
                             fido2.ctap.CtapError.ERR.OPERATION_DENIED)
        else:
            self.assertTrue(False)

    def test_close_window(self):
        rp = {'id': "test-close-window",
              'name': "Don't answer; close the window instead"}
        try:
            open_ctap().make_credential(b'hash', rp, user, key_params)
        except Exception as e:
            self.assertIsInstance(e, fido2.ctap.CtapError)
            self.assertEqual(e.code,
                             fido2.ctap.CtapError.ERR.OPERATION_DENIED)
        else:
            self.assertTrue(False)

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
        result = test_register_and_authenticate()
        self.assertIsInstance(result, fido2.webauthn.AttestedCredentialData)

    def test_tampered_rp_id(self):
        try:
            test_tampered_rp_id()
        except Exception as e:
            self.assertIsInstance(e, fido2.ctap.CtapError)
            self.assertEqual(e.code,
                             fido2.ctap.CtapError.ERR.INVALID_CREDENTIAL)
        else:
            self.assertTrue(False)

    def test_deny_challenge(self):
        user = {'id': b'user_id',
                'displayName': 'auser@example.com',
                'name': "A. User" }
        rp = {'id': "test-deny-challenge", 'name': "Name"}
        dev = open_ctap()
        cred = dev.make_credential(b'hash', rp, user, key_params)
        challenge = b'Y2hhbGxlbmdl'
        try:
            dev.get_assertion(
                rp["id"],
                challenge,
                [{"type": "public-key",
                  "id": cred.auth_data.credential_data.credential_id}],)
        except Exception as e:
            self.assertIsInstance(e, fido2.ctap.CtapError)
            self.assertEqual(e.code,
                             fido2.ctap.CtapError.ERR.OPERATION_DENIED)
        else:
            self.assertTrue(False)

    def test_open_ctap1(self):
        self.assertIsInstance(open_ctap1(), fido2.ctap1.Ctap1)

    def test_u2f_version(self):
        self.assertEqual(open_ctap1().get_version(), 'U2F_V2')

    def test_u2f_register(self):
        clientdata = sha256(b'AAA')
        appid = sha256(b'BBB')
        regdata = open_ctap1().register(clientdata, appid)
        self.assertIsInstance(regdata, fido2.ctap1.RegistrationData)
        regdata.verify(appid, clientdata)

    def test_u2f_authenticate(self):
        clientdata = sha256(b'AAA')
        appid = sha256(b'BBB')
        ctap1 = open_ctap1()
        regdata = ctap1.register(clientdata, appid)
        self.assertIsInstance(regdata, fido2.ctap1.RegistrationData)
        regdata.verify(appid, clientdata)
        auth = ctap1.authenticate(clientdata, appid, regdata.key_handle)
        self.assertIsInstance(auth, fido2.ctap1.SignatureData)
        auth.verify(appid, clientdata, regdata.public_key)

    def test_u2f_client(self):
        s = make_server()
        user = {"id": b'user-reg-id',
                "name": "username",
                "displayName": "displayName"}
        (create_options, state) = s.register_begin(user)
        dev = open_ctaphid_device()
        c = client.Fido2Client(dev, "https://foo.com")
        c._backend = client._Ctap1ClientBackend(dev, client.UserInteraction())
        pub_key=create_options["publicKey"]
        result = c.make_credential(pub_key)
        auth_data = s.register_complete(state, result.client_data,
                                        result.attestation_object)
        credentials = [auth_data.credential_data]
        (aoptions, state) = s.authenticate_begin(credentials)
        rs = c.get_assertion(aoptions["publicKey"])
        r = rs.get_response(0)
        return s.authenticate_complete(state,credentials,
                                       r.credential_id,
                                       r.client_data,
                                       r.authenticator_data,
                                   r.signature)

    def test_u2f_counter(self):
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
        rp = {'id': 'example.com', 'name': 'Example RP'}
        dev = open_ctaphid_device()
        client = fido2.client.Fido2Client(dev, "https://example.com")
        user = {'id': b'user_id', 'name': 'A. User'}
        challenge1 = b'Y2hhbGxlbmdl'
        cred = client.make_credential({
            "rp": rp,
            "user": user,
            "challenge": challenge1,
            "pubKeyCredParams": key_params})
        credential_data = cred.attestation_object.auth_data.credential_data
        public_key = credential_data.public_key
        challenge2 = b'Q0hBTExFTkdF'  # Use a new challenge for each call.
        allow_list = [{'type': 'public-key',
                       'id': credential_data.credential_id}]
        assertions1 = client.get_assertion({
            "rpId": rp["id"],
            "challenge": challenge2,
            "allowCredentials": allow_list})
        assertion1 = assertions1.get_response(0)
        challenge3 = b'yooT1AiB'
        assertions2 = client.get_assertion({
            "rpId": rp["id"],
            "challenge": challenge3,
            "allowCredentials": allow_list})
        assertion2 = assertions2.get_response(0)
        public_key.verify(
            assertion1.authenticator_data + assertion1.client_data.hash,
            assertion1.signature)
        public_key.verify(
            assertion2.authenticator_data + assertion2.client_data.hash,
            assertion2.signature)
        self.assertTrue(assertion1.authenticator_data.counter
                        < assertion2.authenticator_data.counter)

    @unittest.skip("""This fails because we get a "Wrong Channel"
    exception.  It seems that the python-fido2 code is buggy in this
    regard.  I think that it should skip/ignore packets that are not
    sent to the current channel. (USB is more or less a "bus" and if
    there are multiple clients, then every client will see all packets
    on the bus.""")
    def test_multichannel(self):
        dev1 = open_ctaphid_device()
        dev2 = open_ctaphid_device()
        client1 = fido2.client.Fido2Client(dev1, "https://example1.com")
        client2 = fido2.client.Fido2Client(dev2, "https://example2.com")
        rp1 = {'id': 'example1.com', 'name': 'Example RP'}
        rp2 = {'id': 'example2.com', 'name': 'Example RP'}
        user = {'id': b'user_id', 'name': 'A. User'}
        challenge1 = b'Y2hhbGxlbmdl'
        results = [None, None]
        barrier = threading.Barrier(3, timeout=5)
        def make_credential(index, client, rp):
            try:
                results[index] = client.make_credential({
                    "rp": rp,
                    "user": user,
                    "challenge": challenge1,
                    "pubKeyCredParams": key_params})
            except Exception as e:
                results[index] = e
            barrier.wait()
        threading.Thread(target=make_credential,args=(0,client1,rp1)).start()
        threading.Thread(target=make_credential,args=(1,client2,rp2)).start()
        barrier.wait()
        for r in results:
            print(f"{type(r)}")
            if (isinstance(r, fido2.client.ClientError) and
                isinstance(r.cause, fido2.ctap.CtapError)):
                self.assertEqual(r.cause.code,
                                 fido2.ctap.CtapError.ERR.CHANNEL_BUSY)
            else:
                self.assertIsInstance(
                    r,
                    fido2.webauthn.AuthenticatorAttestationResponse)

if __name__ == '__main__':
    unittest.main()
