// brot-glm2 step 3 — EXPRESS SURFACE (ours): express@5.3.0 + body-parser@2.3.0.
// Content-Encoding: br request bodies are inflated by body-parser's raw()
// and json() via zlib.createBrotliDecompress (streaming) — Imperva's proven
// inbound path. Routes:
//   POST /raw   body-parser 2.3.0 raw()          (type */*, limit 256mb)
//   POST /json  body-parser 2.3.0 json()         (limit 256mb)
//   POST /ejson express 5.3.0 BUNDLED express.json() (cover the built-in variant)
//   GET  /health pid + version (restart detector)
// Decompression failures surface as 400 (body-parser catches), errno
// echoed in the response. CRASH = connection reset + pid change.
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const opts = { limit: '256mb' };

const reply = (req, res) => res.json({
  ok: true, len: Buffer.isBuffer(req.body) ? req.body.length
      : (req.body && typeof req.body === 'object') ? Object.keys(req.body).length
      : (req.body ? String(req.body).length : 0)
});

app.get('/health', (req, res) => res.json({ pid: process.pid, v: process.version }));

app.post('/raw', bodyParser.raw(Object.assign({ type: '*/*' }, opts)), reply);
app.post('/json', bodyParser.json(opts), reply);
app.post('/ejson', express.json(opts), reply);

// surface decompress errno + also log full error server-side (captures
// stream 'error' payload body-parser swallows)
app.use((err, req, res, next) => {
  if (err) console.log('ERR', req.path, err.status, err.type, err.errno || '-', err.code || '-',
                       String(err.message).slice(0, 120), err.body && err.body.length);
  if (err && (err.type === 'entity.too.large' || err.status === 413)) {
    return res.status(413).json({ result: 'too-large' });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ result: 'parse-failed', errno: (typeof err.errno === 'number') ? err.errno : null });
  }
  res.status(500).json({ result: 'err', type: err && err.type, errno: (err && typeof err.errno === 'number') ? err.errno : null, msg: String(err && err.message).slice(0, 120) });
});

app.listen(8121, '0.0.0.0', () => console.log('express lane up', process.version));
