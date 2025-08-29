# hdm_service.py
# Robust HDM client for Armenian fiscal registers.
# - Request header: MAGIC(7) + proto(1) + fcode(1) + bodyLen(2, BE) + reserved(1)  => 12 bytes
# - Response header: devices return 10 or 11 bytes (optional reserved byte at the end)
#   * code in bytes [6:8] little-endian on your unit
#   * bodyLen in bytes [8:10] big-endian
# - 3DES/ECB + PKCS7
# - First-key calls use key1 = first 24 bytes of SHA256(password)
# - After login, use session key (24 bytes, base64 in response)
# - Tries proto 0x00 first, then 0x05
# - Tries GET_OPS&DEPS function code 0x01, falling back to 0x21 (some firmwares use 0x21)

import socket
import json
import base64
import hashlib
import threading
import time
from typing import Any, Dict, Optional, Tuple, List

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

HDM_MAGIC = bytes.fromhex("D580D4B4D58400")
PROTO_PREF = (0x00, 0x05)   # your device replies with proto=0; try 0x00 first
FCODE_GET_OPS_DEPS_CANDIDATES = (0x01, 0x21)  # try both
# Common function codes (adjust as your firmware requires)
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
    400: "Request error",
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

def _derive_key1(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    key = DES3.adjust_key_parity(digest[:24])
    return key

def _cipher(key24: bytes) -> DES3:
    return DES3.new(key24, DES3.MODE_ECB)

def _jsond(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")

class HDMClient:
    def __init__(self, host: str, port: int, password: str, *,
                 timeout: float = 10.0,
                 debug: bool = True):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.debug = debug

        self._key1 = _derive_key1(password)
        self._session_key: Optional[bytes] = None
        self._seq = 1
        self._lock = threading.Lock()

    # ---------- utils ----------

    def _d(self, msg: str):
        if self.debug:
            print(f"[DEBUG] {msg}")

    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    # ---------- framing ----------

    def _build_frame(self, fcode: int, enc_body: bytes, proto: int) -> bytes:
        # 12-byte header: MAGIC(7)+proto(1)+fcode(1)+len(2,BE)+reserved(1)
        header = bytearray()
        header += HDM_MAGIC
        header.append(proto & 0xFF)
        header.append(fcode & 0xFF)
        header += len(enc_body).to_bytes(2, "big")
        header.append(0x00)
        return bytes(header) + enc_body

    def _read_resp_header(self, s: socket.socket) -> bytes:
        # Devices often send 10 bytes + optional trailing reserved (1 byte)
        hdr10 = self._recvn(s, 10)
        # Peek for one extra optional byte (non-blocking tiny timeout)
        s.settimeout(0.05)
        try:
            extra = s.recv(1)
        except socket.timeout:
            extra = b""
        finally:
            s.settimeout(self.timeout)
        return hdr10 + extra  # may be 10 or 11 bytes

    @staticmethod
    def _recvn(s: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise HDMError(103, f"Socket closed while expecting {n} bytes")
            buf += chunk
        return buf

    def _open(self) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        return s

    # ---------- crypto ----------

    def _encrypt(self, obj: Dict[str, Any], use_session: bool) -> bytes:
        data = _jsond(obj)
        key = self._session_key if use_session else self._key1
        if not key:
            raise HDMError(102, "Missing session key; call login() first")
        enc = _cipher(key).encrypt(pad(data, 8))
        self._d(f"JSON->enc bytes={len(enc)}")
        return enc

    def _decrypt(self, enc: bytes, use_session: bool) -> Dict[str, Any]:
        if not enc:
            return {}
        key = self._session_key if use_session else self._key1
        plain = unpad(_cipher(key).decrypt(enc), 8)
        return json.loads(plain.decode("utf-8"))

    def _parse_header(self, hdr: bytes) -> Tuple[int, int, int, int]:
        # hdr len is 10 or 11
        if len(hdr) not in (10, 11):
            raise HDMError(103, f"Response header length {len(hdr)} not 10/11",
                           {"raw": hdr.hex().upper()})

        proto = hdr[1]
        # response code bytes [6:8] – little-endian on your unit
        code_le = int.from_bytes(hdr[6:8], "little")
        code_be = int.from_bytes(hdr[6:8], "big")
        code = code_le or code_be
        body_len = int.from_bytes(hdr[8:10], "big")
        reserved = hdr[10] if len(hdr) == 11 else None

        self._d(f"RespHdr={hdr.hex().upper()} Proto={proto} Code={code} BodyLen={body_len} "
                f"{'Reserved='+str(reserved) if reserved is not None else ''}")
        return proto, code, body_len, reserved if reserved is not None else 0

    # ---------- core send ----------

    def _send(self, fcode: int, body: Dict[str, Any], use_session: bool,
              proto_try: Tuple[int, ...]) -> Dict[str, Any]:
        enc = self._encrypt(body or {}, use_session)

        last_err: Optional[Exception] = None
        for proto in proto_try:
            frame = self._build_frame(fcode, enc, proto)
            self._d(f"Request hex (header+enc): {frame.hex().upper()}")

            try:
                with self._open() as s:
                    s.sendall(frame)
                    hdr = self._read_resp_header(s)
                    proto_r, code, blen, _ = self._parse_header(hdr)
                    enc_body = self._recvn(s, blen) if blen > 0 else b""

                if code != 200 and not enc_body:
                    name = ERROR_NAMES.get(code, "Unknown error")
                    raise HDMError(code, f"HDM error ({name}); empty body.")

                resp = self._decrypt(enc_body, use_session)

                if code != 200:
                    name = ERROR_NAMES.get(code, "Unknown error")
                    raise HDMError(code, f"HDM error ({name})", {"response": resp})

                # success
                return resp

            except Exception as e:
                last_err = e
                self._d(f"Attempt with proto=0x{proto:02X} failed: {e}")
                time.sleep(0.1)
                continue

        if isinstance(last_err, HDMError):
            raise last_err
        raise HDMError(400, f"All protocol attempts failed; last={last_err}")

    # ---------- public API ----------

    def get_operators_and_departments(self) -> Dict[str, Any]:
        # Try 0x01 first, then 0x21; try proto 0x00 first, then 0x05
        body = {"password": self.password}
        last_err: Optional[Exception] = None
        for code in FCODE_GET_OPS_DEPS_CANDIDATES:
            try:
                return self._send(code, body, use_session=False, proto_try=PROTO_PREF)
            except Exception as e:
                last_err = e
                self._d(f"GET_OPS&DEPS fcode=0x{code:02X} failed: {e}")
                continue
        if isinstance(last_err, HDMError):
            raise last_err
        raise HDMError(404, "GET_OPERATORS_AND_DEPARTMENTS unsupported by device/firmware")

    def login(self, cashier_id: int, pin: str) -> bytes:
        body = {"password": self.password, "cashier": int(cashier_id), "pin": str(pin)}
        resp = self._send(FCODE["LOGIN"], body, use_session=False, proto_try=PROTO_PREF)
        b64 = resp.get("key")
        if not b64:
            raise HDMError(102, "Login succeeded but no session key returned", resp)
        raw = base64.b64decode(b64)
        if len(raw) != 24:
            raise HDMError(102, f"Session key length != 24 (got {len(raw)})")
        self._session_key = DES3.adjust_key_parity(raw)
        return raw

    def logout(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._send(FCODE["LOGOUT"], body, use_session=True, proto_try=PROTO_PREF)

    def get_device_time(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._send(FCODE["GET_DEVICE_TIME"], body, use_session=True, proto_try=PROTO_PREF)
