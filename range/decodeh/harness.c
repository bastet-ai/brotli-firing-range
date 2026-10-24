/* brotli decode harness: file -> decoder, oracle via exit code + ASan.
 * /decode file.br            one-shot style, dynamically growing output
 *                            (models Node sync decompress: drains everything)
 * /decode --stream file.br   streaming decompressor, 64KB chunks (partial paths)
 * /decode --ring file.br     streaming into a REUSED fixed output buffer
 *                            (models caller-buffer reuse like HTTP servers)
 * /decode --bytes1 file.br   streaming, ONE BYTE of input per call
 *                            (models byte-at-a-time feeds: the internal
 *                            s->buffer.u8[8] append path)
 * /decode --chunk=N file.br  streaming, N input bytes per call
 * /decode --refeed=N ...  after EOF, keep feeding N synthetic bytes
 *                            (0x41) one per call while the decoder stays
 *                            NEEDS_MORE_INPUT-hungry (append-overflow probe;
 *                            harmless no-op once the decoder errors/succeeds)
 * (all streaming modes drain output continuously)
 * /decode --large ...        additionally SetParameter(LARGE_WINDOW=1)
 *                            (models Envoy brotli decompressor, which opts in;
 *                            construct A2 reachability requires large window)
 * Both streaming modes DRAIN output continuously (loop on NEEDS_MORE_OUTPUT
 * as well as NEEDS_MORE_INPUT) — CVE-2026-111497 construct A2 produces
 * 2^24 literals (~16MB) before the trigger; without draining we'd get a
 * false NEEDS_MORE_OUTPUT error long before the block switch fires.
 * exit 0 ok / 2 decoder error / ASan aborts on corruption.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <brotli/decode.h>

static unsigned char *readfile(const char *p, size_t *len) {
  FILE *f = fopen(p, "rb");
  if (!f) { perror("open"); exit(3); }
  fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
  unsigned char *b = malloc(sz ? sz : 1);
  if (fread(b, 1, sz, f) != (size_t)sz) { fprintf(stderr, "short read\n"); exit(3); }
  fclose(f); *len = sz; return b;
}

int main(int argc, char **argv) {
  int mode = 0, large = 0, chunk = 0, refeed = 0; const char *path = argv[argc - 1];
  for (int a = 1; a < argc - 1; ++a) {
    if (!strcmp(argv[a], "--stream")) mode = 1;
    if (!strcmp(argv[a], "--ring")) mode = 2;
    if (!strcmp(argv[a], "--large")) large = 1;
    if (!strcmp(argv[a], "--bytes1")) { mode = 3; chunk = 1; }
    if (!strncmp(argv[a], "--chunk=", 8)) { mode = 3; chunk = atoi(argv[a] + 8); }
    if (!strncmp(argv[a], "--refeed=", 9)) { if (!mode) { mode = 3; chunk = 1; } refeed = atoi(argv[a] + 9); }
  }
  if (mode == 3 && chunk < 1) chunk = 1;
  size_t in_len; unsigned char *in = readfile(path, &in_len);

  BrotliDecoderState *mkstate(void) {
    BrotliDecoderState *t = BrotliDecoderCreateInstance(NULL, NULL, NULL);
    if (large) BrotliDecoderSetParameter(t, BROTLI_DECODER_PARAM_LARGE_WINDOW, 1);
    return t;
  }

  if (mode == 0) {
    /* one-shot style with dynamic output growth */
    BrotliDecoderState *s = mkstate();
    size_t cap = 1 << 20, len = 0;
    unsigned char *out = malloc(cap);
    size_t avail_in = in_len;
    const uint8_t *next_in = in;
    BrotliDecoderResult r;
    for (;;) {
      size_t avail_out = cap - len;
      uint8_t *next_out = out + len;
      r = BrotliDecoderDecompressStream(s, &avail_in, &next_in,
                                        &avail_out, &next_out, NULL);
      len = (size_t)(next_out - out);
      if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
        cap *= 2;
        out = realloc(out, cap);
        continue;
      }
      break;
    }
    fprintf(stderr, "oneshot rc=%d total_out=%zu code=%d\n", (int)r, len,
            (int)BrotliDecoderGetErrorCode(s));
    return r == BROTLI_DECODER_RESULT_SUCCESS ? 0 : 2;
  }
  BrotliDecoderState *s = mkstate();
  size_t in_off = 0;
  const size_t CHUNK = 65536;
  const size_t IN_CHUNK = (mode == 3) ? (size_t)(chunk ? chunk : 1) : in_len;
  unsigned char *fixed = malloc(CHUNK); /* ring: reused buffer, models server reuse */
  unsigned char *ref = refeed ? malloc((size_t)(refeed > 0 ? refeed : 1)) : NULL;
  if (ref) memset(ref, 0x41, (size_t)refeed);
  BrotliDecoderResult r = BROTLI_DECODER_RESULT_ERROR;
  size_t fed_extra = 0;
  for (;;) {
    size_t feed; const uint8_t *src; int from_ref = 0;
    if (in_off < in_len) { feed = in_len - in_off; src = in + in_off; }
    else if (refeed > 0) { feed = 1; src = ref; from_ref = 1; refeed--; }
    else break;
    if (mode == 3 && feed > IN_CHUNK) feed = IN_CHUNK;
    size_t avail_in = feed;
    const uint8_t *next_in = src;
    size_t avail_out = CHUNK; uint8_t *next_out = fixed;
    if (mode == 1) { free(fixed); fixed = malloc(CHUNK); next_out = fixed; }
    r = BrotliDecoderDecompressStream(s, &avail_in, &next_in, &avail_out, &next_out, NULL);
    if (r == BROTLI_DECODER_RESULT_ERROR) {
      fprintf(stderr, "stream error at in_off=%zu code=%d fed_extra=%zu\n",
              in_off, (int)BrotliDecoderGetErrorCode(s), fed_extra);
      return 2;
    }
    if (from_ref) {
      fed_extra++;
      if (next_in == src) refeed++; /* untouched synthetic byte: retry it */
    } else {
      in_off = (size_t)(next_in - in);
    }
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) continue; /* drain + retry */
  }
  fprintf(stderr, "stream done rc=%d code=%d in_off=%zu/%zu fed_extra=%zu\n", (int)r,
          (int)BrotliDecoderGetErrorCode(s), in_off, in_len, fed_extra);
  return r == BROTLI_DECODER_RESULT_SUCCESS ? 0 : 2;
}
