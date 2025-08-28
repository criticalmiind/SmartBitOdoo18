
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
    return data + bytes([padlen]) * padlen


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
        self._last_receipt = None

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
                self._last_receipt = {
                    'ok': True,
                    'fiscal_number': f'AM-{int(time.time())}',
                    'verification_number': f'V-{self.seq:06d}',
                    'rseq': self.seq,
                    'crn': 'CRN-123456',
                    'qr_base64': b64encode(
                        f'QR:{self.seq}'.encode('utf-8')
                    ).decode('ascii'),
                }
                return dict(self._last_receipt)
            elif op == 'print_return_receipt':
                self.seq += 1
                self._last_receipt = {
                    'ok': True,
                    'fiscal_number': f'AMR-{int(time.time())}',
                    'verification_number': f'VR-{self.seq:06d}',
                    'rseq': self.seq,
                    'crn': 'CRN-123456',
                    'qr_base64': b64encode(
                        f'RETURN:{self.seq}'.encode('utf-8')
                    ).decode('ascii'),
                }
                return dict(self._last_receipt)
            elif op == 'cash_in_out':
                return {'ok': True}
            elif op == 'ping':
                return {'ok': True}
            elif op in ('get_last_receipt', 'fetch_last_receipt'):
                if self._last_receipt:
                    data = dict(self._last_receipt)
                    data['ok'] = True
                    return data
                return {'ok': False, 'message': 'No last receipt data in simulator'}
            else:
                return {'ok': False, 'message': 'Unsupported op in simulator'}

        # Placeholder for real hardware protocol.
        # Try multiple on-the-wire formats since some devices require
        # different line endings or no terminator at all. Also handle
        # connection resets gracefully and attempt to parse partial data.

        def _try_exchange(terminator: bytes):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((ip, port))
            chunks = []
            try:
                data = json.dumps(payload).encode('utf-8')
                s.sendall(data + terminator)

                start = time.time()
                while True:
                    try:
                        buf = s.recv(4096)
                    except socket.timeout:
                        break
                    except ConnectionResetError:
                        # If we already received something, treat as end-of-stream
                        if chunks:
                            break
                        raise
                    if not buf:
                        break
                    chunks.append(buf)
                    if b"\n" in buf:
                        break
                    if time.time() - start > 10:
                        break

                raw = b"".join(chunks)
                if not raw:
                    raise Exception("No response from HDM device (empty reply)")

                # For line-delimited protocols, keep up to first newline
                nl = raw.find(b"\n")
                if nl != -1:
                    raw = raw[:nl]

                # Try to decode as UTF-8 JSON first
                try:
                    text = raw.decode('utf-8')
                except UnicodeDecodeError:
                    # Fall back to latin-1 to extract any JSON substring
                    text = raw.decode('latin-1', errors='ignore')

                text_stripped = text.strip()
                if text_stripped:
                    try:
                        return json.loads(text_stripped)
                    except json.JSONDecodeError:
                        start_idx = text_stripped.find('{')
                        end_idx = text_stripped.rfind('}')
                        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                            candidate = text_stripped[start_idx:end_idx + 1]
                            try:
                                return json.loads(candidate)
                            except Exception:
                                pass

                # Some devices respond with binary ACK-only frames (e.g. containing 0x06)
                # to indicate success without a JSON payload. Treat those as ok for
                # operations that don't require a structured response.
                op = (payload or {}).get('op')
                if b"\x06" in raw or (len(raw) <= 12 and any(b for b in raw)):
                    if op in ('login', 'ping', 'cash_in_out', 'print_receipt', 'print_return_receipt'):
                        return {'ok': True, 'ack': True}

                preview = text_stripped[:200] if text_stripped else raw[:32].hex()
                _logger.error("Invalid response from HDM device: %s", preview)
                raise Exception(f"Invalid response from HDM device: {preview}")
            finally:
                try:
                    s.close()
                except Exception:
                    pass

        last_exc = None
        for term in (b"\n", b"", b"\r\n"):
            try:
                return _try_exchange(term)
            except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError, Exception) as e:
                last_exc = e
                # Try next framing style
                continue
        # If everything failed, raise a clean, user-friendly error
        if isinstance(last_exc, ConnectionResetError):
            raise Exception("HDM connection was closed by the device. Verify protocol/terminator and credentials.")
        raise Exception(f"HDM communication failed: {last_exc}")

    def test_connection(self, config):
        """Check that a connection to the HDM device can be established and
        return diagnostic info when possible.

        The previous implementation attempted to send a ``ping`` command and
        waited for a JSON response.  In real deployments some devices simply
        close the socket without replying, which resulted in a timeout even
        though the host and port were correct.  This method now performs a bare
        TCP connection when not running in simulation mode.  If the socket can
        be opened within a short timeout the test is considered successful.
        """

        if self.simulate:
            key = _derive_2key_3des(config.hdm_password or '')
            started = time.time()
            resp = self._send(
                config.hdm_ip, config.hdm_port, key, {'op': 'ping'}
            )
            rtt_ms = int((time.time() - started) * 1000)
            info = {'simulate': True, 'rtt_ms': rtt_ms}
            if isinstance(resp, dict):
                info.update(resp)
            return {'ok': bool(isinstance(resp, dict) and resp.get('ok')), 'info': info}

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(5)
            s.connect((config.hdm_ip, config.hdm_port))
        except socket.timeout:
            raise Exception('Connection timed out')
        finally:
            try:
                s.close()
            except Exception:
                pass
        # Try a ping to obtain device diagnostics, tolerant to ACK-only
        key = _derive_2key_3des(config.hdm_password or '')
        started = time.time()
        try:
            resp = self._send(config.hdm_ip, config.hdm_port, key, {'op': 'ping'})
            rtt_ms = int((time.time() - started) * 1000)
            info = {'ip': config.hdm_ip, 'port': config.hdm_port, 'rtt_ms': rtt_ms}
            if isinstance(resp, dict):
                info.update(resp)
            return {'ok': bool(isinstance(resp, dict) and resp.get('ok')), 'info': info}
        except Exception as e:
            # Even if ping fails, connection was possible; return details
            rtt_ms = int((time.time() - started) * 1000)
            return {'ok': False, 'info': {'ip': config.hdm_ip, 'port': config.hdm_port, 'rtt_ms': rtt_ms, 'error': str(e)}}

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
        resp = self._send(config.hdm_ip, config.hdm_port, key, {
            'op': 'print_receipt',
            'order': order_payload,
            'department': getattr(config, 'hdm_department', None) or 'vat',
            'department_id': getattr(config, 'hdm_department_id', None) or '',
            'seq': self.seq + 1,
        })
        # Track device-reported sequence if available
        if isinstance(resp, dict) and resp.get('ok') and resp.get('rseq'):
            try:
                self.seq = int(resp.get('rseq'))
            except Exception:
                pass
        # If acknowledgment without details, try to fetch last receipt info
        if isinstance(resp, dict) and resp.get('ok') and not any(resp.get(k) for k in ('fiscal_number','verification_number','rseq','crn','qr_base64')):
            try:
                details = self._send(config.hdm_ip, config.hdm_port, key, {'op': 'get_last_receipt'})
                if isinstance(details, dict) and details.get('ok') and any(details.get(k) for k in ('fiscal_number','verification_number','rseq','crn','qr_base64')):
                    return details
                return {'ok': True, 'debug': resp}
            except Exception as e:
                return {'ok': True, 'debug': {'error': str(e), **resp}}
        return resp

    def print_return_receipt(self, config, original_order, return_payload):
        key = _derive_2key_3des(config.hdm_password or '')
        resp = self._send(config.hdm_ip, config.hdm_port, key, {
            'op': 'print_return_receipt',
            'original': {
                'crn': original_order.hdm_crn,
                'rseq': original_order.hdm_rseq,
                'fiscal_number': original_order.hdm_fiscal_number,
            },
            'return': return_payload,
            'department': getattr(config, 'hdm_department', None) or 'vat',
            'department_id': getattr(config, 'hdm_department_id', None) or '',
            'seq': self.seq + 1,
        })
        if isinstance(resp, dict) and resp.get('ok') and resp.get('rseq'):
            try:
                self.seq = int(resp.get('rseq'))
            except Exception:
                pass
        if isinstance(resp, dict) and resp.get('ok') and not any(resp.get(k) for k in ('fiscal_number','verification_number','rseq','crn','qr_base64')):
            try:
                details = self._send(config.hdm_ip, config.hdm_port, key, {'op': 'get_last_receipt'})
                if isinstance(details, dict) and details.get('ok') and any(details.get(k) for k in ('fiscal_number','verification_number','rseq','crn','qr_base64')):
                    return details
                return {'ok': True, 'debug': resp}
            except Exception as e:
                return {'ok': True, 'debug': {'error': str(e), **resp}}
        return resp

    def cash_in_out(self, config, amount, is_cashin, description):
        key = _derive_2key_3des(config.hdm_password or '')
        return self._send(config.hdm_ip, config.hdm_port, key, {
            'op': 'cash_in_out',
            'amount': float(amount),
            'is_cashin': bool(is_cashin),
            'description': description or '',
        })
