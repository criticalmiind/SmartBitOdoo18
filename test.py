# hdm_web.py
# Simple local HTTP server that:
#  - Serves the HTML UI at http://127.0.0.1:9001/
#  - Exposes POST /rpc to forward a single HDM frame to the fiscal device (TCP or TLS)
#
# Usage:
#   python hdm_web.py
#   Open http://127.0.0.1:9001/ in your browser

import base64
import json
import socket
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "127.0.0.1"
PORT = 9001
TIMEOUT = 15.0  # seconds

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>HDM Client (Browser + Python Bridge)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <!-- CryptoJS for TripleDES/SHA256 -->
  <!-- CryptoJS core + deps (required for 3DES) -->
    <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/core.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/enc-utf8.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/cipher-core.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/sha256.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/des.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/tripledes.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/mode-ecb.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/pad-pkcs7.min.js"></script>
  <style>
    :root { color-scheme: dark; }
    body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin:0; background:#0b1020; color:#e5e7eb }
    header { padding:16px 20px; border-bottom:1px solid #1f2937; background:#0b1020; position:sticky; top:0 }
    h1 { font-size:18px; margin:0 }
    main { max-width:1000px; margin:0 auto; padding:20px }
    .card { background:#111827; border:1px solid #334155; border-radius:16px; padding:16px; margin-bottom:16px }
    .grid { display:grid; gap:12px; grid-template-columns:repeat(2,minmax(0,1fr)) }
    label { font-size:12px; color:#93c5fd }
    input, select { width:100%; padding:8px 10px; border-radius:10px; border:1px solid #374151; background:#0f172a; color:#e5e7eb }
    .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center }
    button { padding:10px 14px; border-radius:10px; border:1px solid #2563eb; background:#1d4ed8; color:#fff; cursor:pointer }
    button.secondary { border-color:#6b7280; background:#374151 }
    pre { background:#0f172a; border:1px solid #374151; padding:12px; border-radius:12px; overflow:auto; max-height:45vh }
    small { color:#9ca3af }
    .ok { color:#a7f3d0 } .warn { color:#fde68a } .err { color:#fecaca }
  </style>
</head>
<body>
  <header><h1>HDM Client (Browser UI + Python Bridge)</h1></header>
  <main>
    <div class="card">
      <div class="grid">
        <div><label>HDM IP</label><input id="ip" value="123.123.123.14"></div>
        <div><label>HDM Port</label><input id="port" value="8123"></div>
        <div><label>Fiscal Password</label><input id="password" value="krLGfzRh"></div>
        <div><label>Cashier ID</label><input id="cashier" value="3"></div>
        <div><label>PIN</label><input id="pin" value="4321"></div>
        <div>
          <label>Protocol Version</label>
          <select id="proto">
            <option value="0">0x00</option>
            <option value="5" selected>0x05</option>
          </select>
        </div>
        <div>
          <label>TLS (device socket)</label>
          <select id="usetls">
            <option value="false" selected>No (plain TCP)</option>
            <option value="true">Yes (TLS)</option>
          </select>
        </div>
        <div>
          <label>Timeout (seconds)</label>
          <input id="timeout" value="15">
        </div>
      </div>
      <div style="margin-top:12px" class="row">
        <button id="btnOps">Get Operators & Deps</button>
        <button id="btnLogin">Login</button>
        <button id="btnTime">Get Time</button>
        <button class="secondary" id="btnClear">Clear Log</button>
      </div>
      <small>Tip: if you get connection resets, try switching proto 0x00/0x05 and TLS on/off.</small>
    </div>
    <div class="card">
      <strong>Log</strong>
      <pre id="log"></pre>
    </div>
  </main>

<script>

/* ======== Utils ======== */
const logEl = document.getElementById('log');
function log(msg, cls='') {
  const ts = new Date().toISOString();
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = `[${ts}] ${msg}`;
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}
const HDM_MAGIC = Uint8Array.from([0xD5,0x80,0xD4,0xB4,0xD5,0x84,0x00]);
const FCODE = { GET_OPERATORS_AND_DEPS:1, LOGIN:2, GET_DEVICE_TIME:9 };

function getForm() {
  return {
    ip: document.getElementById('ip').value.trim(),
    port: Number(document.getElementById('port').value.trim()),
    password: document.getElementById('password').value,
    cashier: Number(document.getElementById('cashier').value.trim()),
    pin: document.getElementById('pin').value.trim(),
    proto: Number(document.getElementById('proto').value),
    useTLS: document.getElementById('usetls').value === 'true',
    timeout: Number(document.getElementById('timeout').value) || 15
  };
}

/* ======== Crypto helpers (CryptoJS) ======== */
function u8FromWordArray(wa){
  const u8=new Uint8Array(wa.sigBytes); let idx=0;
  for(let i=0;i<wa.words.length;i++){
    const w=wa.words[i];
    u8[idx++]=(w>>>24)&0xff; if(idx>=u8.length)break;
    u8[idx++]=(w>>>16)&0xff; if(idx>=u8.length)break;
    u8[idx++]=(w>>>8)&0xff;  if(idx>=u8.length)break;
    u8[idx++]=w&0xff;        if(idx>=u8.length)break;
  } return u8;
}
function wordArrayFromU8(u8){
  const words=[]; for(let i=0;i<u8.length;i+=4){
    words.push(((u8[i]||0)<<24)|((u8[i+1]||0)<<16)|((u8[i+2]||0)<<8)|((u8[i+3]||0)));
  }
  return CryptoJS.lib.WordArray.create(words,u8.length);
}
function deriveKey1(password){
  const d = CryptoJS.SHA256(CryptoJS.enc.Utf8.parse(password));
  const k = u8FromWordArray(d).slice(0,24);
  return wordArrayFromU8(k);
}
function enc3DES(jsonStr, keyWA){
  const dataWA = CryptoJS.enc.Utf8.parse(jsonStr);
  const enc = CryptoJS.TripleDES.encrypt(dataWA, keyWA, {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7});
  return u8FromWordArray(enc.ciphertext);
}
function dec3DES(encBytes, keyWA){
  if(!encBytes || encBytes.length===0) return "{}";
  const ctWA = wordArrayFromU8(encBytes);
  const decWA = CryptoJS.TripleDES.decrypt({ciphertext: ctWA}, keyWA, {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7});
  return CryptoJS.enc.Utf8.stringify(decWA);
}

/* ======== Base64 helpers ======== */
function b64Encode(u8){
  let s=""; for(let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64DecodeToU8(b64){
  const s = atob(b64); const u8 = new Uint8Array(s.length);
  for(let i=0;i<s.length;i++) u8[i] = s.charCodeAt(i);
  return u8;
}

/* ======== Frame helpers ======== */
function buildFrame(funcCode, encBody, proto){
  const hdr = new Uint8Array(7+1+1+2+1);
  hdr.set(HDM_MAGIC,0);
  hdr[7]=proto&0xff;
  hdr[8]=funcCode&0xff;
  hdr[9]=(encBody.length>>8)&0xff;
  hdr[10]=encBody.length&0xff;
  hdr[11]=0x00;
  const out=new Uint8Array(hdr.length+encBody.length);
  out.set(hdr,0); out.set(encBody,hdr.length);
  return out;
}
function parseHeader(hdr){
  const proto=hdr[1];
  const codeLE=hdr[6]|(hdr[7]<<8);
  const codeBE=(hdr[6]<<8)|hdr[7];
  const code=codeLE||codeBE;
  const bodyLen=(hdr[8]<<8)|hdr[9];
  return {proto, code, bodyLen};
}

/* ======== HDM Client (browser) ======== */
let seq=1, sessionKey=null;
function nextSeq(){ seq+=1; return seq; }

async function sendRPC({ip,port,useTLS,timeout,frameU8}){
  const res = await fetch("/rpc", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      ip, port, tls: !!useTLS, timeout,
      frame: b64Encode(frameU8)
    })
  });
  const j = await res.json();
  if(!res.ok || j.error){
    throw new Error(j.error || ("HTTP "+res.status));
  }
  return {
    hdr: b64DecodeToU8(j.header),
    body: j.body ? b64DecodeToU8(j.body) : new Uint8Array(0)
  };
}

async function callHDM(fcode, payload, useSession){
  const f = getForm();
  const key = useSession ? sessionKey : deriveKey1(f.password);
  if(useSession && !sessionKey) throw new Error("Missing session key; login first.");
  const enc = enc3DES(JSON.stringify(payload||{}), key);
  const frame = buildFrame(fcode, enc, f.proto);   // ✅ funcCode, encBody, proto
  log(`→ frame[0..11]= ${Array.from(frame.slice(0,12)).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase()}`);
  const {hdr, body} = await sendRPC({ip:f.ip,port:f.port,useTLS:f.useTLS,timeout:f.timeout,frameU8:frame});
  const {proto, code, bodyLen} = parseHeader(hdr);
  log(`← hdr proto=${proto} code=${code} len=${bodyLen}`);
  if(code!==200 && body.length===0) throw new Error(`HDM error ${code} (empty body)`);
  const txt = dec3DES(body, key);
  const resp = txt ? JSON.parse(txt) : {};
  if(code!==200) throw new Error(`HDM error ${code}: ${txt}`);
  return resp;
}

/* ======== Buttons ======== */
document.getElementById('btnOps').onclick = async () => {
  try{
    const f=getForm();
    const resp = await callHDM(FCODE.GET_OPERATORS_AND_DEPS, {password:f.password}, false);
    log("Operators/Deps: "+JSON.stringify(resp), "ok");
  }catch(e){ log("Ops error: "+e.message, "err"); }
};
document.getElementById('btnLogin').onclick = async () => {
  try{
    const f=getForm();
    const resp = await callHDM(FCODE.LOGIN, {password:f.password, cashier:f.cashier, pin:String(f.pin)}, false);
    const b64 = resp.key;
    if(!b64) throw new Error("Login OK but no session key in body");
    const raw = b64DecodeToU8(b64);
    if(raw.length!==24) throw new Error("Session key length != 24");
    sessionKey = wordArrayFromU8(raw);
    log("Login OK; session key set", "ok");
  }catch(e){ log("Login error: "+e.message, "err"); }
};
document.getElementById('btnTime').onclick = async () => {
  try{
    const resp = await callHDM(FCODE.GET_DEVICE_TIME, {seq: nextSeq()}, true);
    log("Device time: "+JSON.stringify(resp), "ok");
  }catch(e){ log("Get time error: "+e.message, "err"); }
};
document.getElementById('btnClear').onclick = ()=>{ logEl.textContent=""; }
</script>
</body>
</html>
"""

class Handler(BaseHTTPRequestHandler):
    def _set_cors(self):
        # Same-origin if you use http://127.0.0.1:9001/ — CORS here just in case
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index.html"):
            self.send_response(200)
            self._set_cors()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode("utf-8"))
            return
        if self.path == "/favicon.ico":
            self.send_response(204); self.end_headers(); return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path != "/rpc":
            self.send_response(404); self.end_headers(); return

        try:
            clen = int(self.headers.get("Content-Length","0"))
            body = self.rfile.read(clen)
            data = json.loads(body.decode("utf-8"))
            ip = data["ip"]
            port = int(data["port"])
            use_tls = bool(data.get("tls", False))
            timeout = float(data.get("timeout", TIMEOUT))
            frame_b64 = data["frame"]
            frame = base64.b64decode(frame_b64)

            # Connect to HDM (TCP or TLS)
            sock = socket.create_connection((ip, port), timeout=timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                # The device probably uses self-signed; skip verification locally
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)
            sock.settimeout(timeout)

            # Send frame
            sock.sendall(frame)

            # Read 12-byte header
            hdr = _recvn(sock, 12)
            # Determine body length (bytes 8..9 BE)
            body_len = (hdr[8] << 8) | hdr[9]
            enc_body = b""
            if body_len > 0:
                enc_body = _recvn(sock, body_len)

            try:
                sock.close()
            except:  # noqa
                pass

            resp = {
                "header": base64.b64encode(hdr).decode("ascii"),
                "body": base64.b64encode(enc_body).decode("ascii") if enc_body else ""
            }
            self.send_response(200)
            self._set_cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode("utf-8"))
        except Exception as e:
            self.send_response(200)  # keep JSON shape
            self._set_cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            out = {"error": f"{type(e).__name__}: {str(e)}"}
            self.wfile.write(json.dumps(out).encode("utf-8"))

def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Socket closed while expecting {n} bytes")
        buf += chunk
    return buf

if __name__ == "__main__":
    print(f"Serving on http://{HOST}:{PORT}")
    with HTTPServer((HOST, PORT), Handler) as httpd:
        httpd.serve_forever()
