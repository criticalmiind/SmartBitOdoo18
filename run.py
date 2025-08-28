import socket
import json
import hashlib
from typing import Tuple, Dict, Any, List

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# --------- YOUR CONNECTION / AUTH ---------
HDM_IP = "123.123.123.14"     # <-- set to your HDM IP
HDM_PORT = 8123               # <-- set to your HDM Port
HDM_PASSWORD = "krLGfzRh"     # <-- fiscal registration password

# --------- CONSTANTS FROM SPEC -----------
PROTO_VERSION = 0x05  # per spec
FUNC_GET_OPS_DEPTS = 0x01  # "Get list of HDM operators and departments" (key1)  (spec lists order; func id 0x01 is used)
MAGIC = bytes.fromhex("D580D4B4D58400")  # Armenian "ՀԴՄ" marker per spec

def sha256_24(password: str) -> bytes:
    """First 24 bytes of SHA256(password) -> 3DES key1 (spec §4.4.3)."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    # TDES key parity: pycryptodome adjusts parity automatically for 24-byte keys
    return digest[:24]

def enc_key1(password: str) -> DES3:
    return DES3.new(sha256_24(password), DES3.MODE_ECB)

def build_request_header(func_code: int, body_len: int) -> bytes:
    """
    Request header format (spec §4.4.1):
      Byte 1-7: D5 80 D4 B4 D5 84 00
      Byte 8  : 05 (protocol)
      Byte 9  : function code
      Byte10-11: body length (Big Endian)
    """
    if not (0 <= body_len <= 0xFFFF):
        raise ValueError("Body length must fit in 2 bytes")
    return (
        MAGIC
        + bytes([PROTO_VERSION])
        + bytes([func_code])
        + body_len.to_bytes(2, "big")
    )

def build_get_ops_depts(password: str) -> bytes:
    """Build request frame for: Get list of operators and departments (spec §4.5.1)."""
    # JSON body per spec: {"password": "<HDM_PASSWORD>"}  (spec §4.5.1)
    body_obj = {"password": password}
    body_json = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")

    # Encrypt with key1 (3DES/ECB/PKCS7) (spec §4.4.3)
    cipher = enc_key1(password)
    enc = cipher.encrypt(pad(body_json, 8))

    # Header + encrypted body (spec §4.4.1)
    header = build_request_header(FUNC_GET_OPS_DEPTS, len(enc))
    frame = header + enc
    return frame

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes (or raise)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

# def parse_response_header(hdr: bytes) -> Tuple[int, int, bytes]:
#     """
#     Response header format (spec §4.4.2), 10 bytes fixed:
#       [0] = 0x00
#       [1] = protocol version (05)
#       [2:6] = program version (4 bytes, informational)
#       [6:8] = response code (Big Endian)
#       [8:10] = response length (Big Endian)
#     Returns: (resp_code_be, body_len_be, progver_bytes)
#     """
#     if len(hdr) < 10:
#         raise ValueError(f"Incomplete response header ({len(hdr)} bytes)")

#     proto = hdr[1]
#     progver = hdr[2:6]
#     resp_code_be = int.from_bytes(hdr[6:8], "big")
#     body_len_be  = int.from_bytes(hdr[8:10], "big")

#     # For diagnostics also compute little-endian interpretations
#     resp_code_le = int.from_bytes(hdr[6:8], "little")
#     body_len_le  = int.from_bytes(hdr[8:10], "little")

#     print(
#         f"[DEBUG] RespHdr hex={hdr.hex().upper()} "
#         f"Proto={proto}, ProgVer={progver.hex().upper()}, "
#         f"RespCodeBE={resp_code_be}, RespCodeLE={resp_code_le}, "
#         f"BodyLenBE={body_len_be}, BodyLenLE={body_len_le}"
#     )
#     return resp_code_be, body_len_be, progver
def parse_response_header(hdr: bytes) -> Tuple[int, int, bytes]:
    if len(hdr) < 10:
        raise ValueError(f"Incomplete response header ({len(hdr)} bytes)")

    proto = hdr[1]
    progver = hdr[2:6]
    # Interpret response code as LITTLE endian
    resp_code = int.from_bytes(hdr[6:8], "little")
    body_len  = int.from_bytes(hdr[8:10], "big")

    print(
        f"[DEBUG] RespHdr hex={hdr.hex().upper()} "
        f"Proto={proto}, ProgVer={progver.hex().upper()}, "
        f"RespCode={resp_code}, BodyLen={body_len}"
    )
    return resp_code, body_len, progver


def decode_response_body(enc_body: bytes, password: str) -> Dict[str, Any]:
    """Decrypt response body with key1 and parse JSON (spec §4.4.3, §4.4.4)."""
    cipher = enc_key1(password)
    plain = unpad(cipher.decrypt(enc_body), 8)
    text = plain.decode("utf-8")
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON parse error: {e}\nPlaintext: {text!r}") from e
    return obj

def query_departments(ip: str, port: int, password: str) -> List[Dict[str, Any]]:
    """
    Returns list of departments (list.d per §4.5.1) or raises an error with details.
    """
    req = build_get_ops_depts(password)

    print(f"[DEBUG] Request hex (header+enc): {req.hex().upper()}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((ip, port))
        s.sendall(req)

        # Per §4.2, first we receive the response header (10 bytes minimum in our doc)
        hdr = recv_exact(s, 10)
        if len(hdr) < 10:
            raise RuntimeError(f"Incomplete response header: {hdr.hex().upper()}")

        resp_code, body_len, _progver = parse_response_header(hdr)

        # Receive the body (if any)
        body = b""
        if body_len > 0:
            body = recv_exact(s, body_len)
            if len(body) != body_len:
                raise RuntimeError(
                    f"Incomplete response body (expected {body_len}, got {len(body)}): {body.hex().upper()}"
                )

        print(f"[DEBUG] Resp body hex: {body.hex().upper()}")

        # Interpret response code per §4.10 (200 = success). If not 200, raise.
        # (Some devices may send BE; we already printed LE for troubleshooting.)
        if resp_code != 200:
            raise RuntimeError(
                f"HDM returned non-success response code {resp_code} with BodyLen={body_len}. "
                "Check integration mode/IP access, protocol version, function code, and password."
            )

        if body_len == 0:
            # On success, body must contain encrypted JSON (spec says 'Fixed 3DES encoded response').
            raise RuntimeError("Success code 200 but empty body — device returned no payload.")

        # Decrypt & parse JSON
        obj = decode_response_body(body, password)

        # Spec’s example field name for the object is "list", which contains 'c' (cashiers) and 'd' (departments)
        # We'll accept either {"list": {...}} or the flattened {"c":..., "d":...} some firmwares use.
        payload = obj.get("list", obj)
        departments = payload.get("d", [])
        return departments

if __name__ == "__main__":
    try:
        deps = query_departments(HDM_IP, HDM_PORT, HDM_PASSWORD)
        print("Departments:", deps)
    except Exception as e:
        print("ERROR:", e)
