from pwn import remote, context
from datetime import datetime
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
        print(req_hmac)
        self.plc.sendline(req_hmac)
        return

    def recv_response(self):
        resp = self.plc.recvline().decode().strip()[-2:]
        if resp == '00':
            resp = 'Turned off.'
        else:
            resp = 'Turned on.'
        return resp

    @staticmethod
    def on_code():
        trans_id = bytes.fromhex(hex(int(datetime.now().timestamp()) % 65536)[2:].zfill(4))
        code = trans_id + b'\x00\x00\x00\x06\x00\x06\x00\x00\x00\x01'
        return code.hex()

    @staticmethod
    def off_code():
        trans_id = bytes.fromhex(hex(int(datetime.now().timestamp()) % 65536)[2:].zfill(4))
        code = trans_id + b'\x00\x00\x00\x06\x00\x06\x00\x00\x02\x00'
        return code.hex()



if __name__ == '__main__':
    hmi = HMI()
    cmd = input('ON/OFF: ').strip()
    if cmd == 'ON':
        code = hmi.on_code()
    else :
        code = hmi.off_code()

    hmi.send_request(code)

    print(hmi.recv_response())


    