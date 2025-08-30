import socket, ssl, json, hashlib, base64, time
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

HOST = "123.123.123.14"
PORTS = [8123]                 # you can add 443 here if your box does TLS on 443
PASSWORD = "krLGfzRh"

HDM_MAGIC = bytes.fromhex("D5 80 D4 B4 D5 84 00")
PROTO_TRY = (0x00, 0x05)
FCODE_TRY = (0x01, 0x21)
LEN_ENDIAN_TRY = ("little", "big")
TLS_TRY = (False, True)        # try both plain and TLS on the same port

def key1(pw: str) -> bytes:
    # First 24 bytes of SHA-256(password), fixed to 3DES odd parity
    raw = hashlib.sha256(pw.encode("utf-8")).digest()[:24]
    return DES3.adjust_key_parity(raw)

def enc_first(obj: dict) -> bytes:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    c = DES3.new(key1(PASSWORD), DES3.MODE_ECB)
    return c.encrypt(pad(data, 8))

def dec_first(enc: bytes) -> dict:
    if not enc:
        return {}
    c = DES3.new(key1(PASSWORD), DES3.MODE_ECB)
    plain = unpad(c.decrypt(enc), 8)
    return json.loads(plain.decode("utf-8"))

def recvn(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return buf

def open_sock(host, port, use_tls, timeout=10.0):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s

def try_once(port, use_tls, proto, fcode, len_endian):
    body = enc_first({"password": PASSWORD})
    header = bytearray()
    header += HDM_MAGIC
    header.append(proto & 0xFF)
    header.append(fcode & 0xFF)
    header += len(body).to_bytes(2, len_endian)
    header.append(0x00)
    frame = bytes(header) + body

    with open_sock(HOST, port, use_tls, timeout=10.0) as s:
        s.sendall(frame)

        # response header: usually 10 bytes, sometimes +1 reserved
        hdr = recvn(s, 10)
        s.settimeout(0.05)
        try:
            extra = s.recv(1)
            if extra:
                hdr += extra
        except socket.timeout:
            pass
        finally:
            s.settimeout(10.0)

        code_le = int.from_bytes(hdr[6:8], "little") if len(hdr) >= 8 else 0
        blen = int.from_bytes(hdr[8:10], "big") if len(hdr) >= 10 else 0
        body_enc = recvn(s, blen) if blen else b""

    # Some firmwares return 0 for success, others 200
    if code_le not in (0, 200):
        try:
            err = dec_first(body_enc)
        except Exception:
            err = {"raw": body_enc.hex().upper()}
        raise RuntimeError(f"code={code_le}, body={err}")

    resp = dec_first(body_enc)
    return resp

def main():
    last_err = None
    for port in PORTS:
        for use_tls in TLS_TRY:
            for proto in PROTO_TRY:
                for fcode in FCODE_TRY:
                    for le in LEN_ENDIAN_TRY:
                        try:
                            print(f"[TRY] host={HOST} port={port} tls={use_tls} proto=0x{proto:02X} fcode=0x{fcode:02X} len={le}")
                            resp = try_once(port, use_tls, proto, fcode, le)
                            dlist = resp.get("d") or resp.get("list", {}).get("d")
                            print(f"[OK ] matched tls={use_tls} proto=0x{proto:02X} fcode=0x{fcode:02X} len={le}")
                            print("\n=== Departments ===")
                            if dlist:
                                for d in dlist:
                                    print(f"ID={d.get('id')}  Name={d.get('name')}  Type={d.get('type')}")
                            else:
                                print(json.dumps(resp, ensure_ascii=False, indent=2))
                            return
                        except Exception as e:
                            last_err = e
                            time.sleep(0.1)
                            continue
    raise SystemExit(f"All attempts failed. Last error: {last_err}")

if __name__ == "__main__":
    main()
