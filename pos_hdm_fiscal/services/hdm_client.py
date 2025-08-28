
# -*- coding: utf-8 -*-
import socket
import json
import time
import logging
from base64 import b64encode, b64decode
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
        # Native protocol constants (from vendor doc)
        self._HDR_MAGIC = bytes.fromhex('D5 80 D4 B4 D5 84 00')  # Armenian HDM marker
        self._PROTO_VER = 0x05
        # Function codes (best-effort mapping from documentation order)
        self._FC = {
            'get_ops_deps': 0x01,
            'login': 0x02,
            'logout': 0x03,
            'print_receipt': 0x04,
            'print_last_copy': 0x05,
            'print_return_receipt': 0x06,
            'set_header_footer': 0x07,
            'set_logo': 0x08,
            'print_report': 0x09,
            'get_receipt_info': 0x0A,
            'cash_in_out': 0x0B,
            'get_datetime': 0x0C,
            'print_template': 0x0D,
            'sync': 0x0E,
            'get_payment_systems': 0x0F,
            'check_emark': 0x10,
        }

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

    # === Native HDM protocol (header + 3DES-ECB) ===
    def _enc3des(self, key24: bytes, data: bytes) -> bytes:
        return DES3.new(key24, DES3.MODE_ECB).encrypt(_pad(data))

    def _dec3des(self, key24: bytes, data: bytes) -> bytes:
        return _unpad(DES3.new(key24, DES3.MODE_ECB).decrypt(data))

    def _recv_all(self, s: socket.socket, nbytes: int, timeout: float = 10.0) -> bytes:
        s.settimeout(timeout)
        chunks = []
        total = 0
        start = time.time()
        while total < nbytes:
            if time.time() - start > timeout:
                raise socket.timeout("HDM recv timeout")
            part = s.recv(nbytes - total)
            if not part:
                break
            chunks.append(part)
            total += len(part)
        return b"".join(chunks)

    def _send_proto(self, ip, port, func_code: int, body: dict, use_session_key: bool, login_key: bytes) -> dict:
        key = self.session_key if use_session_key else login_key
        if not key or len(key) != 24:
            raise Exception('Invalid or missing HDM encryption key')
        payload = dict(body or {})
        if 'seq' not in payload:
            payload['seq'] = self.seq + 1
        raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        enc = self._enc3des(key, raw)
        length = len(enc)
        header = bytearray()
        header += self._HDR_MAGIC
        header.append(self._PROTO_VER)
        header.append(func_code & 0xFF)
        header += bytes([(length >> 8) & 0xFF, length & 0xFF])
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(10)
            s.connect((ip, port))
            s.sendall(header + enc)
            # Response: 11-byte header + encrypted payload
            rh = self._recv_all(s, 11, timeout=10)
            if len(rh) < 11:
                raise Exception('Short HDM response header')
            resp_len = (rh[9] << 8) | rh[10]
            body_enc = b''
            if resp_len:
                body_enc = self._recv_all(s, resp_len, timeout=10)
            if body_enc:
                try:
                    dec = self._dec3des(key, body_enc)
                    txt = dec.decode('utf-8', errors='ignore').strip()
                    if txt:
                        return json.loads(txt)
                except Exception as e:
                    _logger.error('HDM proto decrypt/parse failed: %s', e)
            # No payload: assume ACK success
            return {'ok': True, 'ack': True}
        finally:
            try:
                s.close()
            except Exception:
                pass

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
            # Prefer native login + get datetime for a stronger check
            info = {}
            try:
                login_resp = self._send_proto(config.hdm_ip, config.hdm_port, self._FC['login'], {
                    'password': config.hdm_password or '',
                    'cashier': int(config.hdm_cashier_id or 0) if (config.hdm_cashier_id or '').isdigit() else 0,
                    'pin': config.hdm_cashier_pin or '',
                }, use_session_key=False, login_key=key)
                if isinstance(login_resp, dict) and login_resp.get('session'):
                    try:
                        self.session_key = b64decode(login_resp.get('session'))
                    except Exception:
                        self.session_key = None
                # attempt datetime
                dt = self._send_proto(config.hdm_ip, config.hdm_port, self._FC['get_datetime'], {}, use_session_key=True, login_key=key)
                info.update({'native_ok': True, 'dt_ok': bool(getattr(dt, 'get', lambda k: False)('ok')) if isinstance(dt, dict) else False})
            except Exception:
                pass
            # Fallback to lenient ping channel
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
        if self.simulate:
            resp = self._send(config.hdm_ip, config.hdm_port, key, {'op': 'login'})
            if not resp.get('ok'):
                raise Exception(resp.get('message', 'Login failed'))
            self.session_key = b'DUMMYSESSION12345678901234'[:24]
            self.seq = 0
            return
        resp = self._send_proto(config.hdm_ip, config.hdm_port, self._FC['login'], {
            'password': config.hdm_password or '',
            'cashier': int(config.hdm_cashier_id or 0) if (config.hdm_cashier_id or '').isdigit() else 0,
            'pin': config.hdm_cashier_pin or '',
        }, use_session_key=False, login_key=key)
        if not isinstance(resp, dict):
            raise Exception('Login failed (invalid response)')
        sess = resp.get('session') or resp.get('sessionKey')
        if not sess:
            # Some devices may ACK without returning session; attempt fallback using first key
            if resp.get('ack'):
                self.session_key = key
                self.seq = 0
                return
            raise Exception(resp.get('message', 'Login did not return a session key'))
        try:
            self.session_key = b64decode(sess)
        except Exception:
            raise Exception('Invalid session key returned by device')
        self.seq = 0

    def print_receipt(self, config, order_payload):
        key = _derive_2key_3des(config.hdm_password or '')
        if self.simulate:
            return self._send(config.hdm_ip, config.hdm_port, key, {'op': 'print_receipt', 'order': order_payload, 'seq': self.seq + 1})
        # Build minimal simple receipt request
        paid_total = 0.0
        try:
            paid_total = float(order_payload.get('amount_total') or 0.0)
        except Exception:
            pass
        dep = getattr(config, 'hdm_department_id', None)
        try:
            dep = int(dep) if dep and str(dep).isdigit() else None
        except Exception:
            dep = None
        body = {
            'seq': self.seq + 1,
            'paidAmount': paid_total,
            'paidAmountCard': 0.0,
            'partialAmount': 0.0,
            'prePaymentAmount': 0.0,
            'mode': 1,
            'useExtPOS': False,
            'partnerTin': None,
        }
        if dep is not None:
            body['dep'] = dep
        try:
            resp = self._send_proto(config.hdm_ip, config.hdm_port, self._FC['print_receipt'], body, use_session_key=True, login_key=key)
        except Exception as e:
            return {'ok': False, 'message': str(e)}
        # If response contains receipt fields
        if isinstance(resp, dict) and (resp.get('rseq') or resp.get('fiscal') or resp.get('verificationNumber')):
            try:
                self.seq = int(resp.get('rseq') or (self.seq + 1))
            except Exception:
                self.seq += 1
            qr_txt = resp.get('qr') or ''
            return {
                'ok': True,
                'fiscal_number': resp.get('fiscal'),
                'verification_number': resp.get('verificationNumber'),
                'rseq': resp.get('rseq'),
                'crn': resp.get('crn'),
                'qr_base64': b64encode(qr_txt.encode('utf-8')).decode('ascii') if qr_txt else None,
            }
        # No details, try last copy
        try:
            details = self._send_proto(config.hdm_ip, config.hdm_port, self._FC['print_last_copy'], {'seq': self.seq + 2}, use_session_key=True, login_key=key)
            if isinstance(details, dict) and (details.get('rseq') or details.get('fiscal') or details.get('verificationNumber')):
                try:
                    self.seq = int(details.get('rseq') or (self.seq + 1))
                except Exception:
                    self.seq += 1
                qr_txt = details.get('qr') or ''
                return {
                    'ok': True,
                    'fiscal_number': details.get('fiscal'),
                    'verification_number': details.get('verificationNumber'),
                    'rseq': details.get('rseq'),
                    'crn': details.get('crn'),
                    'qr_base64': b64encode(qr_txt.encode('utf-8')).decode('ascii') if qr_txt else None,
                }
            return {'ok': True, 'details': details}
        except Exception as e:
            return {'ok': False, 'message': str(e)}
        return {'ok': True, 'message': 'Receipt printed, but no fiscal data returned'}

    def print_return_receipt(self, config, original_order, return_payload):
        key = _derive_2key_3des(config.hdm_password or '')
        if self.simulate:
            return self._send(config.hdm_ip, config.hdm_port, key, {'op': 'print_return_receipt', 'seq': self.seq + 1})
        body = {
            'seq': self.seq + 1,
            'receiptId': str(original_order.hdm_rseq or ''),
            'crn': original_order.hdm_crn or '',
        }
        try:
            resp = self._send_proto(config.hdm_ip, config.hdm_port, self._FC['print_return_receipt'], body, use_session_key=True, login_key=key)
            if isinstance(resp, dict) and (resp.get('rseq') or resp.get('fiscal') or resp.get('verificationNumber')):
                try:
                    self.seq = int(resp.get('rseq') or (self.seq + 1))
                except Exception:
                    self.seq += 1
                qr_txt = resp.get('qr') or ''
                return {
                    'ok': True,
                    'fiscal_number': resp.get('fiscal'),
                    'verification_number': resp.get('verificationNumber'),
                    'rseq': resp.get('rseq'),
                    'crn': resp.get('crn'),
                    'qr_base64': b64encode(qr_txt.encode('utf-8')).decode('ascii') if qr_txt else None,
                }
        except Exception:
            pass
        # Try last copy as a fallback
        try:
            details = self._send_proto(config.hdm_ip, config.hdm_port, self._FC['print_last_copy'], {'seq': self.seq + 1}, use_session_key=True, login_key=key)
            if isinstance(details, dict) and (details.get('rseq') or details.get('fiscal') or details.get('verificationNumber')):
                qr_txt = details.get('qr') or ''
                return {
                    'ok': True,
                    'fiscal_number': details.get('fiscal'),
                    'verification_number': details.get('verificationNumber'),
                    'rseq': details.get('rseq'),
                    'crn': details.get('crn'),
                    'qr_base64': b64encode(qr_txt.encode('utf-8')).decode('ascii') if qr_txt else None,
                }
        except Exception:
            pass
        return {'ok': True}

    def cash_in_out(self, config, amount, is_cashin, description):
        key = _derive_2key_3des(config.hdm_password or '')
        if self.simulate:
            return self._send(config.hdm_ip, config.hdm_port, key, {'op': 'cash_in_out'})
        body = {
            'seq': self.seq + 1,
            'amount': float(amount),
            'isCashin': bool(is_cashin),
            'description': description or '',
            'cashierid': int(config.hdm_cashier_id or 0) if (config.hdm_cashier_id or '').isdigit() else 0,
        }
        resp = self._send_proto(config.hdm_ip, config.hdm_port, self._FC['cash_in_out'], body, use_session_key=True, login_key=key)
        return {'ok': True} if isinstance(resp, dict) else {'ok': True}
