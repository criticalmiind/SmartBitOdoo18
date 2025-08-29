# hdm_service.py
# Reusable HDM (Fiscal Register) client.
#
# Implements TCP framing + 3DES(ECB, PKCS7) per spec, two-key scheme,
# sequence numbers, response header parsing, and high-level calls.
#
# Spec references:
# - Request/response headers & protocol v=0x05, function code byte, length (BE). :contentReference[oaicite:4]{index=4}
# - 3DES key #1 = first 24 bytes of SHA-256(password); key #2 = session key from Login. :contentReference[oaicite:5]{index=5}
# - Functions list & JSON bodies (operators+deps, login, logout, print, reports, etc.). :contentReference[oaicite:6]{index=6}
# - Error codes table (e.g., 200 OK; 4xx/5xx/errors 101..196). :contentReference[oaicite:7]{index=7}

import socket
import json
import base64
import hashlib
import threading
from typing import Any, Dict, List, Optional, Tuple

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

HDM_MAGIC = bytes.fromhex("D580D4B4D58400")  # bytes 1–7 “HDM text as indicator” :contentReference[oaicite:8]{index=8}
PROTO_VERSION = 0x05

# Known/documented functions (the spec lists them but does not number them explicitly in the excerpt.
# These codes are a conventional mapping used in the field; adjust if your vendor assigns different IDs.)
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

# Error-code names for friendlier messages (subset; extend as needed). :contentReference[oaicite:9]{index=9}
ERROR_NAMES = {
    200: "OK",
    400: "Request error",
    402: "Unsupported protocol version",
    403: "Access denied (IP/password mismatch or not in Integration Mode)",
    404: "Invalid function code",
    500: "Internal error",
    101: "Login password error",
    102: "Session key encoding error",
    103: "Header format error",
    104: "Sequence number error",
    105: "JSON formatting error",
    141: "Last receipt record missing",
    142: "Last receipt belongs to another user",
    143: "Printer general error",
    144: "Printer initialization error",
    145: "Printer is out of paper",
    151: "No such department / operator not assigned to department",
    191: "Cash in/out amount must be > 0",
    193: "Buyer TIN format incorrect",
    195: "eMark code format error",
    # ... add the rest if useful for your workflows ...
}

class HDMError(Exception):
    def __init__(self, code: int, message: str, details: Optional[Dict[str, Any]] = None):
        self.code = code
        self.details = details or {}
        super().__init__(f"[{code}] {message}")

def _derive_key1(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    key = digest[:24]
    # PyCryptodome needs a “DES3.adjust_key_parity”; but for keys from a hash, parity is acceptable in practice.
    return DES3.adjust_key_parity(key)

def _cipher_ecb(key24: bytes) -> DES3:
    return DES3.new(key24, DES3.MODE_ECB)

# def _pack_request(function_code: int, enc_body: bytes) -> bytes:
#     # Request header = 12 bytes:
#     # [0:7]=MAGIC, [7]=PROTO, [8]=FUNC, [9:11]=length (2 bytes, BE), then encrypted body. :contentReference[oaicite:10]{index=10}
#     header = bytearray()
#     header += HDM_MAGIC
#     header.append(PROTO_VERSION)
#     header.append(function_code & 0xFF)
#     header += len(enc_body).to_bytes(2, "big")
#     return bytes(header) + enc_body
def _pack_request(function_code: int, enc_body: bytes) -> bytes:
    # Request header should be 12 bytes total
    header = bytearray()
    header += HDM_MAGIC                    # 7 bytes
    header.append(PROTO_VERSION)           # 1 byte
    header.append(function_code & 0xFF)    # 1 byte
    header += len(enc_body).to_bytes(2, "big")  # 2 bytes
    header.append(0x00)                    # reserved / filler (1 byte!)
    return bytes(header) + enc_body


def _parse_response_header(hdr: bytes) -> Tuple[int, int, int, int]:
    # Response header (spec sample): byte1=0x00, byte2=protocol, bytes3–6=program ver, 7–8=response code, 9–10=length (BE). :contentReference[oaicite:11]{index=11}
    if len(hdr) < 10:
        raise HDMError(103, "Response header too short", {"raw": hdr.hex()})
    proto = hdr[1]
    prog_ver = int.from_bytes(hdr[2:6], "big")
    resp_code_be = int.from_bytes(hdr[6:8], "big")
    body_len_be = int.from_bytes(hdr[8:10], "big")
    # Many devices actually encode the *code value* little-endian inside those two bytes.
    resp_code_le = int.from_bytes(hdr[6:8], "little")
    return proto, prog_ver, resp_code_be, body_len_be if body_len_be else 0

class HDMClient:
    """
    Thread-safe(ish) HDM client (sequence managed internally).
    JSON request/response per spec; UTF-8; 3DES-ECB with PKCS7.
    - First key = from password (used for GET_OPERATORS_AND_DEPS, LOGIN). :contentReference[oaicite:12]{index=12}
    - Session key = from LOGIN response (Base64 24 bytes), used for the rest. :contentReference[oaicite:13]{index=13}
    - Each request includes monotonically increasing 'seq' (server enforces > last). :contentReference[oaicite:14]{index=14}
    """
    def __init__(self, host: str, port: int, password: str, debug: bool = True, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.debug = debug

        self._seq = 1
        self._lock = threading.Lock()
        self._key1 = _derive_key1(password)
        self._session_key: Optional[bytes] = None

    # ---------- low-level I/O ----------

    def _send_recv(self, request: bytes) -> Tuple[bytes, bytes]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            s.sendall(request)
            hdr = self._recvn(s, 10)
            proto, prog, resp_code_be, body_len = _parse_response_header(hdr)
            if self.debug:
                print(f"[DEBUG] RespHdr hex={hdr.hex().upper()} Proto={proto}, ProgVer={prog:08X}, "
                      f"RespCodeBE={resp_code_be}, BodyLen={body_len}, Total={len(hdr)}")
            body = self._recvn(s, body_len) if body_len else b""
            return hdr, body

    @staticmethod
    def _recvn(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise HDMError(103, f"Socket closed while expecting {n} bytes")
            buf += chunk
        return buf

    # ---------- crypto helpers ----------

    def _encrypt(self, payload: Dict[str, Any], use_session: bool) -> bytes:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        key = self._session_key if use_session else self._key1
        if not key:
            raise HDMError(102, "Missing session key; call login() first")
        enc = _cipher_ecb(key).encrypt(pad(data, 8))
        if self.debug:
            # show header+enc data length only; avoid logging secrets in production
            print(f"[DEBUG] JSON->enc bytes={len(enc)}")
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

    # ---------- request call ----------

    def _call(self, fcode: int, body: Optional[Dict[str, Any]], use_session: bool) -> Dict[str, Any]:
        enc = self._encrypt(body or {}, use_session)
        req = _pack_request(fcode, enc)
        if self.debug:
            print(f"[DEBUG] Request hex (header+enc): {req.hex().upper()}")
        hdr, enc_body = self._send_recv(req)

        proto = hdr[1]
        if proto not in (0, PROTO_VERSION):
            raise HDMError(402, f"Unsupported protocol version {proto}, expected {PROTO_VERSION} or 0")

        # proto = hdr[1]
        # if proto != PROTO_VERSION:
        #     raise HDMError(402, f"Unsupported protocol version {proto}, expected {PROTO_VERSION}")

        resp_code_be = int.from_bytes(hdr[6:8], "big")
        resp_code_le = int.from_bytes(hdr[6:8], "little")
        code = resp_code_le or resp_code_be  # prefer LE if present (common device quirk)

        # If there is no body and code != 200, surface a clear diagnostic.
        if code != 200 and len(enc_body) == 0:
            name = ERROR_NAMES.get(code, "Unknown error")
            raise HDMError(code, f"HDM error ({name}); empty body. "
                                 f"Check Integration Mode/IP allowlist/password/function code.")

        # When OK but empty body, return {}.
        if code == 200 and len(enc_body) == 0:
            return {}

        resp = self._decrypt(enc_body, use_session)
        # Devices may also put "code" in body—trust header first.
        if code != 200:
            name = ERROR_NAMES.get(code, "Unknown error")
            raise HDMError(code, f"HDM error ({name})", {"response": resp})
        return resp

    # ---------- high-level API ----------

    # First-key functions (no session):
    def get_operators_and_departments(self) -> Dict[str, Any]:
        """
        Response fields:
          c: list of operators [{id, name, deps: [deptIds]}]
          d: list of departments [{id, name, type}]  (type = tax type)  :contentReference[oaicite:15]{index=15}
        """
        # Per spec: request body = {"password": "<HDM password>"}  (no seq here) :contentReference[oaicite:16]{index=16}
        body = {"password": self.password}
        return self._call(FCODE["GET_OPERATORS_AND_DEPS"], body, use_session=False)

    def login(self, cashier_id: int, pin: str) -> None:
        """
        On success the device returns {"key": "<base64 24-byte session key>"}; we store it. :contentReference[oaicite:17]{index=17}
        """
        body = {"password": self.password, "cashier": cashier_id, "pin": str(pin)}
        resp = self._call(FCODE["LOGIN"], body, use_session=False)
        b64 = resp.get("key")
        if not b64:
            raise HDMError(102, "Login succeeded but no session key returned", resp)
        raw = base64.b64decode(b64)
        if len(raw) != 24:
            raise HDMError(102, f"Session key length != 24 (got {len(raw)})")
        self._session_key = DES3.adjust_key_parity(raw)
        return raw

    # Session-key functions (seq required by spec). :contentReference[oaicite:18]{index=18}
    def logout(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._call(FCODE["LOGOUT"], body, use_session=True)

    def get_device_time(self) -> Dict[str, Any]:
        # Response: {"dt": "YYYY-MM-DD ..."} per spec. :contentReference[oaicite:19]{index=19}
        body = {"seq": self._next_seq()}
        return self._call(FCODE["GET_DEVICE_TIME"], body, use_session=True)

    def print_report(self, report_type: int,
                     dept_id: Optional[int] = None,
                     cashier_id: Optional[int] = None,
                     transaction_type_id: Optional[int] = None,
                     start_date: Optional[int] = None,
                     end_date: Optional[int] = None) -> Dict[str, Any]:
        """
        X/Z etc. report; provide one optional filter at a time. :contentReference[oaicite:20]{index=20}
        """
        body = {"seq": self._next_seq(), "reportType": report_type}
        if dept_id is not None:
            body["deptId"] = dept_id
        elif cashier_id is not None:
            body["cashierId"] = cashier_id
        elif transaction_type_id is not None:
            body["transactionTypeId"] = transaction_type_id
        if start_date is not None:
            body["startDate"] = start_date
        if end_date is not None:
            body["endDate"] = end_date
        return self._call(FCODE["PRINT_REPORT"], body, use_session=True)

    def list_payment_systems(self) -> Dict[str, Any]:
        # Response: {"PaymentSystems":[{"code":1,"name":"Cash"},...]} :contentReference[oaicite:21]{index=21}
        body = {"seq": self._next_seq()}
        return self._call(FCODE["LIST_PAYMENT_SYSTEMS"], body, use_session=True)

    def cash_in_out(self, amount: float, is_cashin: bool, cashier_id: Optional[int] = None,
                    description: Optional[str] = None) -> Dict[str, Any]:
        # Cash operations (session) per spec. :contentReference[oaicite:22]{index=22}
        body = {"seq": self._next_seq(), "amount": float(amount), "isCashin": bool(is_cashin)}
        if cashier_id is not None:
            body["cashierid"] = int(cashier_id)
        if description:
            body["description"] = description
        return self._call(FCODE["CASH_IN_OUT"], body, use_session=True)

    # Receipt-related (abbreviated; the spec includes full field list & examples). :contentReference[oaicite:23]{index=23} :contentReference[oaicite:24]{index=24}
    def print_receipt(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        payload must already include the documented fields (mode/dep/items, payment amounts, etc.)
        We add/override the required 'seq'.
        """
        body = dict(payload)
        body["seq"] = self._next_seq()
        return self._call(FCODE["PRINT_RECEIPT"], body, use_session=True)

    def print_last_copy(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._call(FCODE["PRINT_LAST_COPY"], body, use_session=True)

    def print_return(self, crn: str, receipt_id: str) -> Dict[str, Any]:
        body = {"seq": self._next_seq(), "crn": crn, "receiptId": str(receipt_id)}
        return self._call(FCODE["PRINT_RETURN"], body, use_session=True)

    def get_receipt_info(self, **kwargs) -> Dict[str, Any]:
        """
        Wrapper over 4.5.7 Get Receipt Information (supports partial return context). :contentReference[oaicite:25]{index=25}
        Caller passes any allowed fields; we inject seq.
        """
        body = dict(kwargs)
        body["seq"] = self._next_seq()
        return self._call(FCODE["GET_RECEIPT_INFO"], body, use_session=True)

    def set_header_footer(self, headers: List[Dict[str, Any]], footers: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Header/footer formatting options per spec. :contentReference[oaicite:26]{index=26}
        body = {"seq": self._next_seq(), "headers": headers, "footers": footers}
        return self._call(FCODE["SET_HEADER_FOOTER"], body, use_session=True)

    def set_header_logo(self, base64_bitmap: str) -> Dict[str, Any]:
        # Bitmap ≤ 4-bit colors, base64. :contentReference[oaicite:27]{index=27}
        body = {"seq": self._next_seq(), "headerLogo": base64_bitmap}
        return self._call(FCODE["SET_HEADER_LOGO"], body, use_session=True)

    def sync(self) -> Dict[str, Any]:
        body = {"seq": self._next_seq()}
        return self._call(FCODE["SYNC"], body, use_session=True)

    def check_emark(self, emark: str) -> Dict[str, Any]:
        # eMark rules (length, ASCII set, escaping) in spec. :contentReference[oaicite:28]{index=28}
        body = {"seq": self._next_seq(), "eMark": emark}
        return self._call(FCODE["CHECK_EMARK"], body, use_session=True)
