# hdm_service.py
# Robust HDM client (Armenian fiscal register variants).
# - Request header: MAGIC(7) + proto(1) + fcode(1) + bodyLen(2, *endianness varies by model*) + reserved(1) => 12 bytes
# - Response header: 10 or 11 bytes (optional final reserved byte); code at [6:8] LITTLE-ENDIAN on your unit; bodyLen [8:10] BIG-ENDIAN.
# - Crypto: 3DES/ECB + PKCS7; key1 = first 24 bytes of SHA-256(password); session key (24 bytes, base64) after login.
# - Retries matrix: proto ∈ {0x00, 0x05} × len_endian ∈ {"little", "big"} × (optional TLS/plain)

import socket
import json
import base64
import hashlib
import time
from typing import Any, Dict, Optional, Tuple, List

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

HDM_MAGIC = bytes.fromhex("D580D4B4D58400")
PROTO_TRY = (0x00, 0x05)                      # your unit reports proto=0; keep 0 then 5
LEN_ENDIAN_TRY = ("little", "big")            # critical: devices differ here!
TRY_TLS = False                               # set True if your box is TLS-only
FCODE_GET_OPS_DEPS = (0x01, 0x21)             # some firmwares use 0x21

FCODE = {
    "LOGIN": 0x02,
    "LOGOUT": 0x03,
    "PRINT_RECEIPT": 0x04,
    "PRINT_LAST_COPY": 0x05,
    "PRINT_RETURN": 0x06,
    "GET_RECEIPT_INFO": 0x07,
    "CASH_IN_OUT": 0x08,
    "GET_DEVICE_TIME": 0x09,
    "PRINT_TEMPLATE": 0x0A,
    "PRINT_REPORT": 0x0B,
    "SET_HEADER_FOOTER": 0x0C,
    "SET_HEADER_LOGO": 0x0D,
    "SYNC": 0x0E,
    "LIST_PAYMENT_SYSTEMS": 0x0F,
    "CHECK_EMARK": 0x10,
}

ERROR_NAMES = {
    200: "OK",
    400: "Request error / transport",
    402: "Unsupported protocol version",
    403: "Access denied",
    404: "Invalid function code",
    500: "Internal error",
    101: "Login password error",
    102: "Session key encoding / missing",
    103: "Header / framing error",
    104: "Sequence number error",
    105: "JSON formatting error",
    141: "Last receipt record missing",
    142: "Last receipt belongs to another user",
    143: "Printer general error",
    144: "Printer initialization error",
    145: "Printer is out of paper",
    151: "No such department / operator not assigned",
    191: "Cash in/out amount must be > 0",
    193: "Buyer TIN format incorrect",
    195: "eMark code format error",
}

class HDMError(Exception):
    def __init__(self, code: int, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.details = details or {}

def _key1(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return DES3.adjust_key_parity(digest[:24])

def _cipher(key24: bytes) -> DES3:
    return DES3.new(key24, DES3.MODE_ECB)

def _jsonb(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")

class HDMClient:
    def __init__(self, host: str, port: int, password: str, *, timeout: float = 10.0, debug: bool = True):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.debug = debug

        self._key1 = _key1(password)
        self._session: Optional[bytes] = None
        self._seq = 1

    # -------------- utilities --------------

    def _d(self, msg: str):
        if self.debug:
            print(f"[DEBUG] {msg}")

    # -------------- transport --------------

    def _open(self, use_tls: bool) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        s.settimeout(self.timeout)
        return s

    @staticmethod
    def _recvn(s: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise HDMError(103, f"Socket closed while expecting {n} bytes")
            buf += chunk
        return buf

    def _read_resp_header(self, s: socket.socket) -> bytes:
        # Most devices send 10 bytes, some append a reserved byte (11th)
        hdr10 = self._recvn(s, 10)
        s.settimeout(0.05)
        try:
            extra = s.recv(1)
        except socket.timeout:
            extra = b""
        finally:
            s.settimeout(self.timeout)
        return hdr10 + extra  # 10 or 11 bytes

    # -------------- framing --------------

    def _build_frame(self, fcode: int, enc_body: bytes, proto: int, len_endian: str) -> bytes:
        # Header: 12 bytes total
        header = bytearray()
        header += HDM_MAGIC                               # 7
        header.append(proto & 0xFF)                       # 1
        header.append(fcode & 0xFF)                       # 1
        header += len(enc_body).to_bytes(2, len_endian)   # 2  <<< IMPORTANT
        header.append(0x00)                               # 1 reserved
        return bytes(header) + enc_body

    def _parse_resp_header(self, hdr: bytes) -> Tuple[int, int, int]:
        if len(hdr) not in (10, 11):
            raise HDMError(103, f"Response header length {len(hdr)} not 10/11",
                           {"raw": hdr.hex().upper()})
        proto = hdr[1]
        code = int.from_bytes(hdr[6:8], "little")  # LE on your unit
        blen = int.from_bytes(hdr[8:10], "big")    # BE body length (observed)
        self._d(f"RespHdr={hdr.hex().upper()} Proto={proto} Code={code} BodyLen={blen}")
        return proto, code, blen

    # -------------- crypto --------------

    def _encrypt(self, obj: Dict[str, Any], use_session: bool) -> bytes:
        data = _jsonb(obj)
        key = self._session if use_session else self._key1
        if not key:
            raise HDMError(102, "Missing session key; call login() first")
        enc = _cipher(key).encrypt(pad(data, 8))
        self._d(f"JSON->enc bytes={len(enc)}")
        return enc

    def _decrypt(self, enc: bytes, use_session: bool) -> Dict[str, Any]:
        if not enc:
            return {}
        key = self._session if use_session else self._key1
        plain = unpad(_cipher(key).decrypt(enc), 8)
        return json.loads(plain.decode("utf-8"))

    # -------------- core send --------------

    def _send(self, fcode: int, body: Dict[str, Any], use_session: bool) -> Dict[str, Any]:
        enc_body = self._encrypt(body or {}, use_session)

        last_err: Optional[Exception] = None
        tls_try = (False, True) if TRY_TLS else (False,)

        for proto in PROTO_TRY:
            for le in LEN_ENDIAN_TRY:
                for use_tls in tls_try:
                    frame = self._build_frame(fcode, enc_body, proto, le)
                    self._d(f"Request hex (header+enc): {frame.hex().upper()}")

                    try:
                        with self._open(use_tls) as s:
                            s.sendall(frame)
                            hdr = self._read_resp_header(s)
                            _, code, blen = self._parse_resp_header(hdr)
                            body_enc = self._recvn(s, blen) if blen > 0 else b""

                        if code != 200 and not body_enc:
                            name = ERROR_NAMES.get(code, "Unknown error")
                            raise HDMError(code, f"HDM error ({name}); empty body.")

                        resp = self._decrypt(body_enc, use_session)

                        if code != 200:
                            name = ERROR_NAMES.get(code, "Unknown error")
                            raise HDMError(code, f"HDM error ({name})", {"response": resp})

                        return resp

                    except Exception as e:
                        last_err = e
                        self._d(f"Attempt proto=0x{proto:02X}, len_endian={le}, tls={use_tls} failed: {e}")
                        time.sleep(0.1)
                        continue

        if isinstance(last_err, HDMError):
            raise last_err
        raise HDMError(400, f"All protocol attempts failed; last={last_err}")

    # -------------- public API --------------

    def get_operators_and_departments(self) -> Dict[str, Any]:
        body = {"password": self.password}
        last_err: Optional[Exception] = None
        for fcode in FCODE_GET_OPS_DEPS:
            try:
                return self._send(fcode, body, use_session=False)
            except Exception as e:
                last_err = e
                self._d(f"GET_OPS&DEPS fcode=0x{fcode:02X} failed: {e}")
                continue
        if isinstance(last_err, HDMError):
            raise last_err
        raise HDMError(404, "GET_OPERATORS_AND_DEPARTMENTS unsupported by device/firmware")

    def login(self, cashier_id: int, pin: str) -> bytes:
        body = {"password": self.password, "cashier": int(cashier_id), "pin": str(pin)}
        resp = self._send(FCODE["LOGIN"], body, use_session=False)
        b64 = resp.get("key")
        if not b64:
            raise HDMError(102, "Login succeeded but no session key returned", resp)
        raw = base64.b64decode(b64)
        if len(raw) != 24:
            raise HDMError(102, f"Session key length != 24 (got {len(raw)})")
        self._session = DES3.adjust_key_parity(raw)
        return raw

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def get_device_time(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._send(FCODE["GET_DEVICE_TIME"], body, use_session=True)

    # Add more wrappers (print_report, print_receipt, etc.) as needed ...
