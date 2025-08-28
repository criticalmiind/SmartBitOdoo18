import socket
import json
import hashlib
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# fiscal registration information is 

# ip 123.123.123.14

# port 8123

# department 1

# fiscal registration password :  krLGfzRh

# Cashir id 3

# Cashir PIN 3

HDM_IP = "123.123.123.14"
HDM_PORT = 8123
HDM_PASSWORD = "krLGfzRh"

def get_first_key(password: str) -> bytes:
    """Generate 3DES key from SHA256(password)."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return digest[:24]  # first 24 bytes

def build_request(password: str, seq=1) -> bytes:
    """Builds the HDM request for 'Get List of Operators and Departments'."""
    # JSON body
    req_obj = {"password": password}
    req_data = json.dumps(req_obj, ensure_ascii=False).encode("utf-8")

    # Encrypt with 3DES (key1)
    key = get_first_key(password)
    cipher = DES3.new(key, DES3.MODE_ECB)
    enc_data = cipher.encrypt(pad(req_data, 8))

    # HDM Header
    header = bytes.fromhex("D580D4B4D58400")  # HDM magic
    header += bytes([5])  # protocol version
    header += bytes([1])  # function code (Get list of operators & deps)
    header += len(enc_data).to_bytes(2, "big")

    return header + enc_data

def parse_response(resp: bytes, password: str):
    """Decrypt and parse JSON from HDM response."""
    # Skip HDM response header (first 10 bytes after protocol info)
    # Header format documented in section 4.4.2
    enc_data = resp[10:]

    key = get_first_key(password)
    cipher = DES3.new(key, DES3.MODE_ECB)
    data = unpad(cipher.decrypt(enc_data), 8)

    return json.loads(data.decode("utf-8"))

def get_departments():
    req = build_request(HDM_PASSWORD)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HDM_IP, HDM_PORT))
        s.sendall(req)
        resp = s.recv(8192)  # receive up to 8KB

    result = parse_response(resp, HDM_PASSWORD)
    return result.get("d", [])  # departments list

if __name__ == "__main__":
    deps = get_departments()
    print("Departments:", deps)
