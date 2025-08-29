// bridge.js — WebSocket ⇄ TCP relay (no third-party API)
// Usage: node bridge.js
// Then in the HTML, set Bridge URL = ws://127.0.0.1:9001 and your HDM ip/port in the query (?ip=...&port=...&tls=0/1)

const http = require('http');
const WebSocket = require('ws');
const net = require('net');
const tls = require('tls');
const url = require('url');

const server = http.createServer();
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  const { query } = url.parse(req.url, true);
  const ip = query.ip;
  const port = Number(query.port || 8123);
  const useTLS = query.tls === '1';

  let socket;
  const onError = (e) => { try { ws.close(); } catch(_){} };
  const onClose = () => { try { ws.close(); } catch(_){} };

  function connect() {
    return new Promise((resolve, reject) => {
      const opts = { host: ip, port, rejectUnauthorized: false };
      socket = useTLS ? tls.connect(opts, () => resolve()) : net.connect(opts, () => resolve());
      socket.on('error', reject);
      socket.on('close', onClose);
    });
  }

  connect().then(() => {
    ws.on('message', (data) => {
      // data = single TCP request frame from browser
      socket.write(Buffer.from(data));
      // Read header (12 bytes), then body(n), and send each as separate WS messages.
      readN(socket, 12)
        .then(hdr => {
          ws.send(hdr);
          const bodyLen = hdr.readUInt16BE(8);
          if (bodyLen > 0) {
            return readN(socket, bodyLen).then(body => ws.send(body));
          }
        })
        .catch(onError);
    });
  }).catch(onError);

  ws.on('close', () => { if (socket) try { socket.destroy(); } catch(_){} });
});

function readN(sock, n) {
  return new Promise((resolve, reject) => {
    let bufs = [], total = 0;
    const onData = (chunk) => {
      bufs.push(chunk); total += chunk.length;
      if (total >= n) {
        sock.removeListener('data', onData);
        const buf = Buffer.concat(bufs, total);
        resolve(buf.slice(0, n));
        // push back extra bytes (unlikely in this simple request/response flow)
        const rest = buf.slice(n);
        if (rest.length) sock.unshift(rest);
      }
    };
    sock.on('data', onData);
    sock.once('error', reject);
    sock.once('close', () => reject(new Error('socket closed')));
  });
}

server.listen(9001, () => {
  console.log('WebSocket bridge on ws://127.0.0.1:9001');
});
