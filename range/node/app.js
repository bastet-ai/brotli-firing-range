// Node lane: decompresses uploaded bodies with the EMBEDDED decoder.
// POST /decompress  body = raw .br bytes -> 200 + decompressed length,
// or 500 on error. ASan NOT here: this is the exploitation-shape oracle
// (crash = connection death / process exit; the container restart is the signal).
const http = require('http');
const zlib = require('zlib');
http.createServer((req, res) => {
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
