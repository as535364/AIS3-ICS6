#!/usr/bin/env python3
from Cryptodome.Hash import HMAC, SHA256

SECRET_KEY = b'XXXXXXXX'

class PLC:
    def __init__(self):
        self.secret_key = SECRET_KEY

    def verify(self, req, hmac):
        h = HMAC.new(self.secret_key, digestmod = SHA256)
        h.update(req.encode())
        try:
            h.hexverify(hmac)
            return True
        except ValueError:
            return False

    def recv_request_and_respond(self, req_hmac):
        req, hmac = req_hmac.split('||')
        if not self.verify(req, hmac):
            return False, ""
        # handle the request
        resp = "OK"
        return True, resp

if __name__ == '__main__':
    plc = PLC()
    req_hmac = input().strip()
    verdict, resp = plc.recv_request_and_respond(req_hmac)
    if verdict == False:
        print("INVALID REQUEST")
    else:
        print(resp)
