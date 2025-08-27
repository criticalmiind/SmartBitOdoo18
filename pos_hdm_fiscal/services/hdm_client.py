
# -*- coding: utf-8 -*-
import socket
import json
import time
import logging
from base64 import b64encode
from Crypto.Cipher import DES3
from Crypto.Hash import SHA256

_logger = logging.getLogger(__name__)

def _pad(data: bytes, block=8) -> bytes:
    padlen = block - (len(data) % block)
    return data + bytes([padlen])*padlen

def _unpad(data: bytes) -> bytes:
    padlen = data[-1]
    if padlen < 1 or padlen > 8:
        raise ValueError('Invalid padding')
    return data[:-padlen]

def _derive_2key_3des(password: str) -> bytes:
    h = SHA256.new(password.encode('utf-8')).digest()
    k1k2 = h[:16]
    return k1k2 + k1k2[:8]

class HDMClient:
    def __init__(self, simulate=False):
        self.simulate = simulate
        self.sock = None
        self.session_key = None
        self.seq = 0
        self.closed = False

    def is_closed(self):
        return self.closed

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.closed = True

    def _send(self, ip, port, login_key, payload: dict) -> dict:
        if self.simulate:
            op = payload.get('op')
            if op == 'login':
                self.session_key = b'FAKESESSIONKEY012345678901'[:24]
                return {'ok': True, 'session': 'sim-session'}
            elif op == 'print_receipt':
                self.seq += 1
                return {
                    'ok': True,
                    'fiscal_number': f'AM-{int(time.time())}',
                    'verification_number': f'V-{self.seq:06d}',
                    'rseq': self.seq,
                    'crn': 'CRN-123456',
                    'qr_base64': b64encode(f'QR:{self.seq}'.encode('utf-8')).decode('ascii'),
                }
            elif op == 'print_return_receipt':
                self.seq += 1
                return {
                    'ok': True,
                    'fiscal_number': f'AMR-{int(time.time())}',
                    'verification_number': f'VR-{self.seq:06d}',
                    'rseq': self.seq,
                    'crn': 'CRN-123456',
                    'qr_base64': b64encode(f'RETURN:{self.seq}'.encode('utf-8')).decode('ascii'),
                }
            elif op == 'cash_in_out':
                return {'ok': True}
            elif op == 'ping':
                return {'ok': True}
            else:
                return {'ok': False, 'message': 'Unsupported op in simulator'}

        # Placeholder for real hardware protocol.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, port))
        try:
            data = json.dumps(payload).encode('utf-8')
            s.sendall(data)
            buf = s.recv(8192)
            try:
                text = buf.decode('utf-8')
            except UnicodeDecodeError:
                text = buf.decode('latin-1')
            return json.loads(text)
        finally:
            s.close()

    def test_connection(self, config) -> bool:
        key = _derive_2key_3des(config.hdm_password or '')
        resp = self._send(config.hdm_ip, config.hdm_port, key, {'op': 'ping'})
        return bool(resp.get('ok'))

    def ensure_login(self, config):
        if self.session_key:
            return
        key = _derive_2key_3des(config.hdm_password or '')
        resp = self._send(config.hdm_ip, config.hdm_port, key, {
            'op': 'login',
            'cashier_id': config.hdm_cashier_id or '',
            'cashier_pin': config.hdm_cashier_pin or '',
        })
        if not resp.get('ok'):
            raise Exception(resp.get('message', 'Login failed'))
        self.session_key = b'DUMMYSESSION12345678901234'[:24]
        self.seq = 0

    def print_receipt(self, config, order_payload):
        key = _derive_2key_3des(config.hdm_password or '')
        return self._send(config.hdm_ip, config.hdm_port, key, {
            'op': 'print_receipt',
            'order': order_payload,
            'seq': self.seq + 1,
        })

    def print_return_receipt(self, config, original_order, return_payload):
        key = _derive_2key_3des(config.hdm_password or '')
        return self._send(config.hdm_ip, config.hdm_port, key, {
            'op': 'print_return_receipt',
            'original': {
                'crn': original_order.hdm_crn,
                'rseq': original_order.hdm_rseq,
                'fiscal_number': original_order.hdm_fiscal_number,
            },
            'return': return_payload,
            'seq': self.seq + 1,
        })

    def cash_in_out(self, config, amount, is_cashin, description):
        key = _derive_2key_3des(config.hdm_password or '')
        return self._send(config.hdm_ip, config.hdm_port, key, {
            'op': 'cash_in_out',
            'amount': float(amount),
            'is_cashin': bool(is_cashin),
            'description': description or '',
        })
