// Node lane: decompresses uploaded bodies with the EMBEDDED decoder.
// POST /decompress      body = raw .br bytes -> one-shot brotliDecompressSync.
// POST /decompress-stream (brot-glm2 step 1) — streaming oracle:
//   createBrotliDecompress fed in small pieces (default 16B) with REAL pump
//   semantics: write -> (wait drain) -> yield to event loop -> write again.
//   Mirrors fetch/undici + express body-parser streaming more closely than
//   one-shot; each piece gets its own threadpool dispatch, so a decoder that
//   lies NEEDS_MORE_INPUT keeps getting re-pumped with fresh input — the
//   condition our C harness (feed-to-EOF-then-stop) never exercised.
// Observables per request: HTTP result, zlib errno/code/message, timing.
// Crash signal: connection reset (curl 52/56) + /health pid change (restart).
// GET /health -> pid + version (restart detection via pid change).
const http = require('http');
const zlib = require('zlib');

function handleStream(req, res) {
  const chunkSize = Math.max(1, parseInt(req.url.split('?chunk=')[1], 10) || 16);
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const t0 = process.hrtime.bigint();
    const d = zlib.createBrotliDecompress({ maxOutputLength: 1 << 28 });
    let outBytes = 0;
    const finish = (code, obj) => {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(Object.assign({ ms: +ms.toFixed(1), out: outBytes }, obj)));
    };
    d.on('data', c => { outBytes += c.length; });
    d.on('end', () => finish(200, { result: 'ok' }));
    d.on('error', e => finish(500, {
      result: 'err',
      errno: (typeof e.errno === 'number') ? e.errno : null,
      code: e.code || null,
      msg: String(e.message).slice(0, 200)
    }));
    (async () => {
      for (let i = 0; i < body.length; i += chunkSize) {
        const piece = body.slice(i, Math.min(i + chunkSize, body.length));
        if (!d.write(piece)) {
          await new Promise(r => d.once('drain', r));
        } else {
          await new Promise(r => setImmediate(r)); // yield: per-piece dispatch
        }
      }
      d.end();
    })().catch(e => finish(500, { result: 'pump-err', msg: String(e && e.message).slice(0, 200) }));
  });
}

http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200); return res.end(JSON.stringify({ pid: process.pid, v: process.version }));
  }
  if (req.url.startsWith('/decompress-stream')) return handleStream(req, res);
  if (req.url !== '/decompress') { res.writeHead(200); return res.end('brotli-lane ' + process.version); }
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    try {
      const out = zlib.brotliDecompressSync(body, { maxOutputLength: 1 << 28 });
      res.writeHead(200); res.end('ok ' + out.length);
    } catch (e) {
      res.writeHead(500); res.end('err ' + e.message);
    }
  });
}).listen(8121, '0.0.0.0', () => console.log('node lane up', process.version));
