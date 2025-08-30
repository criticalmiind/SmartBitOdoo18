import socket, json, hashlib, base64, time
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

HOST = "123.123.123.14"
PORT = 8123
PASSWORD = "krLGfzRh"

HDM_MAGIC = bytes.fromhex("D5 80 D4 B4 D5 84 00")  # "HDM" magic
PROTO_TRY = (0x05, 0x00)                            # devices vary
FCODE_TRY = (0x01, 0x21)                            # observed variants for ops+deps
LEN_ENDIAN_TRY = ("big", "little")                 # request length field varies by model

def key1(pw: str) -> bytes:
    # first 24 bytes of sha256(password) with 3DES parity
    digest = hashlib.sha256(pw.encode("utf-8")).digest()[:24]
    # adjust parity manually (simple mask; many devices accept raw 24 bytes too)
    def adj(b: int) -> int:
        # set odd parity on each byte
        return (b & 0xFE) | (bin(b & 0xFE).count("1") % 2 == 0)
    return bytes(int(adj(x)) for x in digest)

def enc_first_key(obj: dict) -> bytes:
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    c = DES3.new(key1(PASSWORD), DES3.MODE_ECB)
    return c.encrypt(pad(data, 8))

def dec_first_key(enc: bytes) -> dict:
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

def try_once(proto: int, fcode: int, len_endian: str) -> dict:
    body = enc_first_key({"password": PASSWORD})  # per spec, this call needs only password
    header = bytearray()
    header += HDM_MAGIC
    header.append(proto & 0xFF)
    header.append(fcode & 0xFF)
    header += len(body).to_bytes(2, len_endian)
    header.append(0x00)

    frame = bytes(header) + body

    with socket.create_connection((HOST, PORT), timeout=10.0) as s:
        s.sendall(frame)

        # response header is usually 10 bytes, sometimes 11 (extra reserved)
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

        # Parse: many units put code at [6:8] little-endian and bodyLen at [8:10] big-endian.
        # Some show code==0 for success. Accept both styles.
        code_le = int.from_bytes(hdr[6:8], "little") if len(hdr) >= 8 else 0
        blen = int.from_bytes(hdr[8:10], "big") if len(hdr) >= 10 else 0

        enc_body = recvn(s, blen) if blen else b""

    # allow 0 or 200 as success (both observed in docs/devices)
    if code_le not in (0, 200):
        # try to decrypt anyway to expose any error JSON
        try:
            err = dec_first_key(enc_body)
        except Exception:
            err = {"raw": enc_body.hex().upper()}
        raise RuntimeError(f"HDM responded code={code_le}, body={err}")

    return dec_first_key(enc_body)

def main():
    last_err = None
    for proto in PROTO_TRY:
        for fcode in FCODE_TRY:
            for le in LEN_ENDIAN_TRY:
                try:
                    resp = try_once(proto, fcode, le)
                    # Expected shape: {"c":[{...operators...}], "d":[{id,name,type}, ...]}
                    dlist = resp.get("d") or resp.get("list", {}).get("d")
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
