// brot-glm2 step 4 — FETCH-VICTIM (ours): node 24.22.0 image doing
// fetch('http://evil:8121/vec/<name>') and READING the response — undici
// advertises br by default (verified via evil-origin logs) and decompresses
// Content-Encoding: br responses through streaming zlib as network chunks
// arrive. POST /check-url with JSON {name, dir} triggers the fetch; result
// surfaces undici's decompression failure (TypeError with zlib cause,
// errno echoed when present). CRASH = connection reset + pid change.
const http = require('http');

http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200); return res.end(JSON.stringify({ pid: process.pid, v: process.version })); }
  if (req.url !== '/check-url') { res.writeHead(200); return res.end('fetch-victim ' + process.version); }
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString()); } catch { res.writeHead(400); return res.end('bad json'); }
    const t0 = process.hrtime.bigint();
    const url = 'http://evil:8121/vec/' + encodeURIComponent(body.name) + '?dir=' + (body.dir || 'constructs');
    const finish = o => {
      o.ms = +(Number(process.hrtime.bigint() - t0) / 1e6).toFixed(1);
      res.writeHead(o.result === 'ok' ? 200 : 500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(o));
    };
    fetch(url, { cache: 'no-store' }).then(async r => {
      if (!r.ok) return finish({ result: 'http-' + r.status });
      const b = await r.arrayBuffer();          // force full streaming decompress
      finish({ result: 'ok', len: b.byteLength });
    }).catch(e => {
      const cause = e && e.cause;
      finish({
        result: 'err',
        errno: (cause && typeof cause.errno === 'number') ? cause.errno
             : (typeof e.errno === 'number') ? e.errno : null,
        code: (cause && cause.code) || e.code || null,
        msg: String(e.message).slice(0, 160)
      });
    });
  });
}).listen(8121, '0.0.0.0', () => console.log('fetch victim up', process.version));
