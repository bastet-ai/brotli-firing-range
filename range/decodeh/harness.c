/* brotli decode harness: file -> decoder, oracle via exit code + ASan.
 * /decode file.br            one-shot style, dynamically growing output
 *                            (models Node sync decompress: drains everything)
 * /decode --stream file.br   streaming decompressor, 64KB chunks (partial paths)
 * /decode --ring file.br     streaming into a REUSED fixed output buffer
 *                            (models caller-buffer reuse like HTTP servers)
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
  int mode = 0, large = 0; const char *path = argv[argc - 1];
  for (int a = 1; a < argc - 1; ++a) {
    if (!strcmp(argv[a], "--stream")) mode = 1;
    if (!strcmp(argv[a], "--ring")) mode = 2;
    if (!strcmp(argv[a], "--large")) large = 1;
  }
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
  unsigned char *fixed = malloc(CHUNK); /* ring: reused buffer, models server reuse */
  BrotliDecoderResult r = BROTLI_DECODER_RESULT_ERROR;
  for (;;) {
    size_t avail_in = in_len - in_off;
    const uint8_t *next_in = in + in_off;
    size_t avail_out = CHUNK; uint8_t *next_out = fixed;
    if (mode == 1) { free(fixed); fixed = malloc(CHUNK); next_out = fixed; }
    r = BrotliDecoderDecompressStream(s, &avail_in, &next_in, &avail_out, &next_out, NULL);
    in_off = (size_t)(next_in - in);
    if (r == BROTLI_DECODER_RESULT_ERROR) {
      fprintf(stderr, "stream error at in_off=%zu code=%d\n", in_off,
              (int)BrotliDecoderGetErrorCode(s));
      return 2;
    }
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) continue; /* drain + retry */
    if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && in_off < in_len) continue;
    break;
  }
  fprintf(stderr, "stream done rc=%d code=%d\n", (int)r,
          (int)BrotliDecoderGetErrorCode(s));
  return r == BROTLI_DECODER_RESULT_SUCCESS ? 0 : 2;
}
