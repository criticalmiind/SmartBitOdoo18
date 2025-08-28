import socket
import json
import hashlib
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Fiscal registration info
HDM_IP = "123.123.123.14"
HDM_PORT = 8123
HDM_PASSWORD = "krLGfzRh"

def get_first_key(password: str) -> bytes:
    """Generate 3DES key from SHA256(password)."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return digest[:24]  # first 24 bytes

def build_request(password: str) -> bytes:
    """Build HDM request for 'Get List of Operators and Departments'."""
    # JSON body
    req_obj = {"password": password}
    req_data = json.dumps(req_obj, ensure_ascii=False).encode("utf-8")

    # Encrypt JSON with 3DES using first key
    key = get_first_key(password)
    cipher = DES3.new(key, DES3.MODE_ECB)
    enc_data = cipher.encrypt(pad(req_data, 8))

    # HDM Header
    header = bytes.fromhex("D580D4B4D58400")  # magic
    header += bytes([5])  # protocol version
    header += bytes([1])  # function code = Get list of operators & deps
    header += len(enc_data).to_bytes(2, "big")  # length

    return header + enc_data

def parse_response(resp: bytes, password: str):
    """Decrypt and parse JSON from HDM response."""
    # Extract encrypted payload length (bytes 9–10 = resp[8:10])
    resp_len = int.from_bytes(resp[8:10], "big")

    # Encrypted body starts at byte 11 (index 10)
    enc_data = resp[10:10 + resp_len]
    if not enc_data:
        raise ValueError("No encrypted body found in HDM response")

    # Decrypt with first key
    key = get_first_key(password)
    cipher = DES3.new(key, DES3.MODE_ECB)
    data = unpad(cipher.decrypt(enc_data), 8)

    return json.loads(data.decode("utf-8"))

def get_departments():
    req = build_request(HDM_PASSWORD)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HDM_IP, HDM_PORT))
        s.sendall(req)

        # First read 10-byte header
        header = b""
        while len(header) < 10:
            chunk = s.recv(10 - len(header))
            if not chunk:
                raise RuntimeError("Socket closed before header received")
            header += chunk

        # Determine body length
        resp_len = int.from_bytes(header[8:10], "big")

        # Now read the full encrypted body
        body = b""
        while len(body) < resp_len:
            chunk = s.recv(resp_len - len(body))
            if not chunk:
                raise RuntimeError("Socket closed before full body received")
            body += chunk

        resp = header + body

    result = parse_response(resp, HDM_PASSWORD)
    return result.get("d", [])

if __name__ == "__main__":
    deps = get_departments()
    print("Departments:", deps)
