# hdm_service.py
# Reusable HDM (Fiscal Register) client with robust TLS/protocol fallbacks.
# - TCP framing: magic(7) + proto(1) + fcode(1) + len(2, BE) + reserved(1) + enc_body
# - Crypto: 3DES-ECB, PKCS7, key1 = first 24 bytes of SHA-256(password), key2 = session key from Login (24 bytes b64)
# - Response header: 12 bytes; code in bytes 6..7 (devices often encode little-endian)

import socket
import json
import base64
import hashlib
import threading
import time
import ssl
from typing import Any, Dict, List, Optional, Tuple

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# ---- constants / tables ----

HDM_MAGIC = bytes.fromhex("D580D4B4D58400")  # 7 bytes
PROTO_VERSION_DEFAULT = 0x05                 # many devices prefer 0x05; some require 0x00

FCODE = {
    "GET_OPERATORS_AND_DEPS": 0x01,
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
    403: "Access denied (IP allowlist/Integration Mode/Password)",
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
        self.code = code
        self.details = details or {}
        super().__init__(f"[{code}] {message}")

def _derive_key1(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    key = DES3.adjust_key_parity(digest[:24])
    return key

def _cipher_ecb(key24: bytes) -> DES3:
    return DES3.new(key24, DES3.MODE_ECB)

# ---- client ----

class HDMClient:
    """
    Thread-safe-ish HDM client with automatic transport/protocol fallbacks.
    """
    def __init__(self, host: str, port: int, password: str,
                 debug: bool = True, timeout: float = 10.0,
                 proto_version: int = PROTO_VERSION_DEFAULT,
                 use_tls: bool = False, tls_verify: bool = True):
        self.host = host
        self.port = port
        self.password = password
        self.debug = debug
        self.timeout = timeout

        # preferred settings (will update if fallback finds a working combo)
        self.proto_version = proto_version
        self.use_tls = use_tls
        self.tls_verify = tls_verify

        self._seq = 1
        self._lock = threading.Lock()
        self._key1 = _derive_key1(password)
        self._session_key: Optional[bytes] = None

    # ---------- debug helpers ----------

    def _dprint(self, msg: str):
        if self.debug:
            print(f"[DEBUG] {msg}")

    # ---------- header / framing ----------

    def _build_frame(self, func_code: int, enc_body: bytes, proto_version: int) -> bytes:
        header = bytearray()
        header += HDM_MAGIC                      # 7
        header.append(proto_version & 0xFF)      # 1
        header.append(func_code & 0xFF)          # 1
        header += len(enc_body).to_bytes(2, "big")  # 2
        header.append(0x00)                      # 1 (reserved)
        return bytes(header) + enc_body

    def _parse_resp_header(self, hdr: bytes) -> Tuple[int, int, bytes]:
        if len(hdr) != 12:
            raise HDMError(103, f"Response header length != 12 (got {len(hdr)})",
                           {"raw": hdr.hex().upper()})
        proto = hdr[1]
        progver = hdr[2:6]
        # Many devices encode code little-endian in 6..7:
        code_le = int.from_bytes(hdr[6:8], "little")
        code_be = int.from_bytes(hdr[6:8], "big")
        body_len = int.from_bytes(hdr[8:10], "big")
        reserved = hdr[10]

        self._dprint(f"RespHdr={hdr.hex().upper()} Proto={proto} CodeLE={code_le} CodeBE={code_be} "
                     f"BodyLen={body_len} Reserved={reserved}")
        code = code_le or code_be
        return code, body_len, progver

    @staticmethod
    def _recvn(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise HDMError(103, f"Socket closed while expecting {n} bytes")
            buf += chunk
        return buf

    def _open_socket(self, use_tls: bool) -> socket.socket:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if not use_tls:
            return raw
        ctx = ssl.create_default_context()
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=self.host)

    # ---------- crypto helpers ----------

    def _encrypt(self, payload: Dict[str, Any], use_session: bool) -> bytes:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        key = self._session_key if use_session else self._key1
        if not key:
            raise HDMError(102, "Missing session key; call login() first")
        enc = _cipher_ecb(key).encrypt(pad(data, 8))
        self._dprint(f"JSON->enc bytes={len(enc)}")
        return enc

    def _decrypt(self, enc_data: bytes, use_session: bool) -> Dict[str, Any]:
        if not enc_data:
            return {}
        key = self._session_key if use_session else self._key1
        data = unpad(_cipher_ecb(key).decrypt(enc_data), 8)
        return json.loads(data.decode("utf-8"))

    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    # ---------- core call with fallbacks ----------

    def _alt_proto(self, p: int) -> int:
        return 0x00 if p != 0x00 else 0x05

    def _call(self, fcode: int, body: Optional[Dict[str, Any]], use_session: bool) -> Dict[str, Any]:
        enc = self._encrypt(body or {}, use_session)

        # Build a fallback matrix: (use_tls, proto)
        preferred = (self.use_tls, self.proto_version)
        alt = (self.use_tls, self._alt_proto(self.proto_version))
        swap_tls = (not self.use_tls, self.proto_version)
        swap_both = (not self.use_tls, self._alt_proto(self.proto_version))

        tried = []
        last_err: Optional[Exception] = None

        for use_tls, proto in [preferred, alt, swap_tls, swap_both]:
            if (use_tls, proto) in tried:
                continue
            tried.append((use_tls, proto))

            frame = self._build_frame(fcode, enc, proto)
            self._dprint(f"Request hex (header+enc): {frame.hex().upper()}")

            try:
                with self._open_socket(use_tls) as s:
                    mode = "TLS" if use_tls else "plain"
                    self._dprint(f"TCP connected to {self.host}:{self.port} ({mode}, proto=0x{proto:02X})")
                    s.settimeout(self.timeout)

                    s.sendall(frame)
                    hdr = self._recvn(s, 12)
                    code, body_len, _ = self._parse_resp_header(hdr)
                    enc_body = self._recvn(s, body_len) if body_len > 0 else b""

                    # if no body and not OK:
                    if code != 200 and not enc_body:
                        name = ERROR_NAMES.get(code, "Unknown error")
                        raise HDMError(code, f"HDM error ({name}); empty body.")

                    # decrypt (session or first-key)
                    resp = self._decrypt(enc_body, use_session)

                    if code != 200:
                        name = ERROR_NAMES.get(code, "Unknown error")
                        raise HDMError(code, f"HDM error ({name})", {"response": resp})

                    # lock in the working combo
                    self.use_tls = use_tls
                    self.proto_version = proto
                    return resp

            except (ConnectionResetError, socket.timeout, OSError, HDMError) as e:
                last_err = e
                self._dprint(f"Attempt with tls={use_tls}, proto=0x{proto:02X} failed: {e}")
                # Try next combination
                time.sleep(0.2)
                continue

        # If we got here, all combinations failed
        if isinstance(last_err, HDMError):
            raise last_err
        raise HDMError(400, f"Unable to reach/handshake with {self.host}:{self.port}. "
                            f"Tried TLS/plain and proto 0x00/0x05. "
                            f"Check Integration Mode, IP allowlist, correct port, and TLS requirement.",
                       {"last_error": str(last_err) if last_err else None})

    # ---------- high-level API ----------

    def get_operators_and_departments(self) -> Dict[str, Any]:
        # Body for first-key calls typically includes the plain password
        # (encrypted with key1 derived from that same password).
        body = {"password": self.password}
        return self._call(FCODE["GET_OPERATORS_AND_DEPS"], body, use_session=False)

    def login(self, cashier_id: int, pin: str) -> bytes:
        body = {"password": self.password, "cashier": int(cashier_id), "pin": str(pin)}
        resp = self._call(FCODE["LOGIN"], body, use_session=False)
        b64 = resp.get("key")
        if not b64:
            raise HDMError(102, "Login succeeded but no session key in body", resp)
        raw = base64.b64decode(b64)
        if len(raw) != 24:
            raise HDMError(102, f"Session key length != 24 (got {len(raw)})")
        self._session_key = DES3.adjust_key_parity(raw)
        return raw

    def logout(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._call(FCODE["LOGOUT"], body, use_session=True)

    def get_device_time(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._call(FCODE["GET_DEVICE_TIME"], body, use_session=True)

    def print_report(self, report_type: int,
                     dept_id: Optional[int] = None,
                     cashier_id: Optional[int] = None,
                     transaction_type_id: Optional[int] = None,
                     start_date: Optional[int] = None,
                     end_date: Optional[int] = None) -> Dict[str, Any]:
        body = {"seq": self._next_seq(), "reportType": int(report_type)}
        if dept_id is not None:
            body["deptId"] = int(dept_id)
        elif cashier_id is not None:
            body["cashierId"] = int(cashier_id)
        elif transaction_type_id is not None:
            body["transactionTypeId"] = int(transaction_type_id)
        if start_date is not None:
            body["startDate"] = int(start_date)
        if end_date is not None:
            body["endDate"] = int(end_date)
        return self._call(FCODE["PRINT_REPORT"], body, use_session=True)

    def list_payment_systems(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._call(FCODE["LIST_PAYMENT_SYSTEMS"], body, use_session=True)

    def cash_in_out(self, amount: float, is_cashin: bool,
                    cashier_id: Optional[int] = None,
                    description: Optional[str] = None) -> Dict[str, Any]:
        body = {"seq": self._next_seq(), "amount": float(amount), "isCashin": bool(is_cashin)}
        if cashier_id is not None:
            body["cashierid"] = int(cashier_id)
        if description:
            body["description"] = str(description)
        return self._call(FCODE["CASH_IN_OUT"], body, use_session=True)

    def print_receipt(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = dict(payload)
        body["seq"] = self._next_seq()
        return self._call(FCODE["PRINT_RECEIPT"], body, use_session=True)

    def print_last_copy(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._call(FCODE["PRINT_LAST_COPY"], body, use_session=True)

    def print_return(self, crn: str, receipt_id: str) -> Dict[str, Any]:
        body = {"seq": self._next_seq(), "crn": str(crn), "receiptId": str(receipt_id)}
        return self._call(FCODE["PRINT_RETURN"], body, use_session=True)

    def get_receipt_info(self, **kwargs) -> Dict[str, Any]:
        body = dict(kwargs)
        body["seq"] = self._next_seq()
        return self._call(FCODE["GET_RECEIPT_INFO"], body, use_session=True)

    def set_header_footer(self, headers: List[Dict[str, Any]], footers: List[Dict[str, Any]]) -> Dict[str, Any]:
        body = {"seq": self._next_seq(), "headers": headers, "footers": footers}
        return self._call(FCODE["SET_HEADER_FOOTER"], body, use_session=True)

    def set_header_logo(self, base64_bitmap: str) -> Dict[str, Any]:
        body = {"seq": self._next_seq(), "headerLogo": base64_bitmap}
        return self._call(FCODE["SET_HEADER_LOGO"], body, use_session=True)

    def sync(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._call(FCODE["SYNC"], body, use_session=True)

    def check_emark(self, emark: str) -> Dict[str, Any]:
        body = {"seq": self._next_seq(), "eMark": str(emark)}
        return self._call(FCODE["CHECK_EMARK"], body, use_session=True)
