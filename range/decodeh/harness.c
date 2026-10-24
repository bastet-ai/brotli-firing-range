/* brotli decode harness: file -> decoder, oracle via exit code + ASan.
 * /decode file.br            one-shot BrotliDecoderDecompress
 * /decode --stream file.br   streaming decompressor, 64KB chunks (partial paths)
 * /decode --ring file.br     streaming into a REUSED fixed ring output buffer
 *                            (models caller-buffer reuse like HTTP servers)
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
  int mode = 0; const char *path = argv[argc - 1];
  if (argc > 2 && !strcmp(argv[1], "--stream")) mode = 1;
  if (argc > 2 && !strcmp(argv[1], "--ring")) mode = 2;
  size_t in_len; unsigned char *in = readfile(path, &in_len);

  if (mode == 0) {
    size_t avail_out = in_len * 16 + 65536; /* decoder max expansion bound-ish; harness generous */
    unsigned char *out = malloc(avail_out);
    size_t total = avail_out;
    BrotliDecoderResult r = BrotliDecoderDecompress(in_len, in, &total, out);
    fprintf(stderr, "rc=%d total_out=%zu\n", (int)r.result, total);
    return r.result == BROTLI_DECODER_RESULT_SUCCESS ? 0 : 2;
  }
  BrotliDecoderState *s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
  size_t in_off = 0;
  const size_t CHUNK = 65536;
  unsigned char *fixed = malloc(CHUNK); /* ring: reused buffer, models server reuse */
  BrotliDecoderResult r = BROTLI_DECODER_RESULT_ERROR;
  do {
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
  } while (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && in_off < in_len);
  fprintf(stderr, "stream done rc=%d\n", (int)r.result);
  return r.result == BROTLI_DECODER_RESULT_SUCCESS ? 0 : 2;
}
