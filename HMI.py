from pwn import remote, context
from Cryptodome.Hash import HMAC, SHA256

PLC_IP = '127.0.0.1'
PLC_PORT = 8989
SECRET_KEY = b'XXXXXXXX'

class HMI:
    def __init__(self):
        self.plc = remote(PLC_IP, PLC_PORT)
        self.secret_key = SECRET_KEY

    def send_request(self, req):
        hmac = HMAC.new(self.secret_key, digestmod = SHA256)
        hmac.update(req.encode())
        hmac = hmac.hexdigest()
        req_hmac = f"{req}||{hmac}"
        self.plc.sendline(req_hmac)
        return

    def recv_response(self):
        resp = self.plc.recvline().decode().strip()
        return resp

if __name__ == '__main__':
    hmi = HMI()
    hmi.send_request('hello')
    print(hmi.recv_response())