#!/usr/bin/env python3

from flask import Flask, render_template

import base64
import struct

from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

def decode_b64url(string):
    return base64.urlsafe_b64decode(string + '=') # FIXME

class Responder:
    def __init__(self, privkey: str):
        privkey_raw = decode_b64url(privkey)

        self.privkey = X25519PrivateKey.from_private_bytes(privkey_raw)
        self.pubkey = self.privkey.public_key()
        self.pubkey_raw = self.pubkey.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    def get_response(self, payload, challenge):
        challenge_raw = decode_b64url(challenge)
        peer_pub = X25519PublicKey.from_public_bytes(challenge_raw)

        dh_secret = self.privkey.exchange(peer_pub)

        hmac = HMAC(dh_secret, SHA256())
        hmac.update(payload)
        sig = hmac.finalize()

        code = struct.unpack('<Q', sig[0:8])[0]
        code = code % 1000000000

        code_str = "%09u" % code
        return code_str[0:3] + " " + code_str[3:6] + " " + code_str[6:9]

app = Flask(__name__)

# private zGRMAXRoSKwMZG5EM-_B-s8oxTfICcfBiN1PAHCCqVo
# public  Zng28LIYphqbbwqEfvcT4nAshzazNE5lDuSvRJjrSgQ
responder = Responder('zGRMAXRoSKwMZG5EM-_B-s8oxTfICcfBiN1PAHCCqVo')

@app.route("/<node>/<user>/<challenge>")
def get_standalone(node, user, challenge):
    payload = ("%s/%s" % (node, user)).encode('ascii')
    code = responder.get_response(payload, challenge)

    return render_template('response.html', node=node, code=code)

@app.route("/<group>/<node>/<user>/<challenge>")
def get_grouped(group, node, user, challenge):
    payload = b''.join(map(lambda x: x.encode('ascii') + b'\x00', [group, node, user]))
    code = responder.get_response(payload, challenge)

    return render_template('response.html', node=node, code=code)
