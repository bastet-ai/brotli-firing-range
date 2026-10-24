// Bun lane: same shape on Bun's embedded brotli.
const server = Bun.serve({
  hostname: "0.0.0.0",
  port: 8122,
  async fetch(req) {
    if (req.url.endsWith("/decompress")) {
      const body = new Uint8Array(await req.arrayBuffer());
      try {
        const ds = new DecompressionStream("br");
        const out = await new Response(
          new Blob([body]).stream().pipeThrough(ds)
        ).arrayBuffer();
        return new Response("ok " + out.byteLength);
      } catch (e) {
        return new Response("err " + e.message, { status: 500 });
      }
    }
    return new Response("bun-lane " + Bun.version);
  },
});
console.log("bun lane up", Bun.version);
