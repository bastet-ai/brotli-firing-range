# Rung 6 — Verdict & defensive write-up notes (brot-glm1)

## DoS-vs-RCE honest verdict row

| claim | verdict | evidence |
|---|---|---|
| Memory corruption / RCE via b418fa8 flaw | **NOT DEMONSTRATED — verdict: CPU livelock DoS only** | 339-run ASan sweep (corpus/constructs+seeds x oneshot/stream/ring x asan-vuln/asan-ctrl): zero ASan reports; the vulnerable loop (`NextLiteralBlock <-> CommandInner`, v1.2.0 decode.c) reads/writes nothing — it re-checks `block_length[0]==0` forever with the bit reader untouched. No write primitive exists on this path. |
| Reachable DoS (C level) | **CONFIRMED** | 54-byte stream (corpus/constructs/a2_large_min.br): brotli v1.2.0 & v1.1.0 + LARGE_WINDOW decodeh-asan rig: rc=124, 100% CPU, never returns, all 3 harness modes. Patched v1.2.1: clean `ERROR_FORMAT_BLOCK_SWITCH` (-17) in ~0.4-40ms. Same source in docker rigs as in local pristine-tag builds. |
| Reachable via deployed products in this range | **NO (all three lanes honest negatives)** | Node 22.23.3/22.23.4 (zlib brotliDecompressSync), Bun 1.4.3 (DecompressionStream "brotli"), Envoy 1.39.2 (brotli request-decompressor): all reject the stream cleanly. None call `BrotliDecoderSetParameter(LARGE_WINDOW=1)`, which our reachability proof shows is REQUIRED: with standard windows (ring <= 2^24 = window cap), the pre-existing `meta_block_remaining_len < 0` guards (BLOCK_LENGTH_1/-9, BLOCK_LENGTH_2/-10, fired at every ring wrap / metablock end / post-command boundary) plus ring geometry (pos+bl+1 <= ring unreachable when sum(inserts)+sum(copies) <= MLEN <= 2^24) make the trigger state unreachable. Proven empirically: every standard-window shape dies -9/-13 on both vuln and ctrl rigs. Envoy additionally caps at 100x compression-bomb ratio. |

## Who IS exposed (defensive relevance)

Any embedding that enables **Large Window Brotli decoding**
(BROTLI_DECODER_PARAM_LARGE_WINDOW=1) and links brotli v1.0.3..v1.2.0:
a 54-byte `Content-Encoding: br` body burns ~2^24 literal decodes (~40ms,
no output) then spins one worker thread/event loop at 100% CPU
FOREVER (never returns; no error; watchdog-free apps hang permanently).
Also: brotli v1.1.0 line confirmed livelocking; v1.0.9 rejects cleanly.

## What to block / patch (disclosure-adjacent notes)

1. Patch: brotli >= 1.2.1 (and 1.1.1 / 1.0.10 lines); embeddings: bump
   vendored brotli. Envoy pins brotli v1.2.0 as of 1.39.2 — upgrade to
   1.39.3+/1.40.0 per advisory even though the request-decompressor does
   not enable large window today (defense in depth for the copy).
2. Ingress defense: cap/deadline CPU per decompression
   (Envoy: per-request watchdogs + decompressor bomb ratio; WAFs can
   pre-validate Content-Encoding: br bodies against the patched decoder).
3. Detection signature (this construct): brotli stream whose large-window
   WBITS prefix (1,000,001,0 + 6-bit wbits>=10) is followed by a metablock
   declaring MLEN == 2^24 exactly with NBLTYPESL==1 — a combination no
   legitimate encoder emits (real encoders never produce a 16MiB
   single-block-type metablock driven to the switch with a 2^24+1 insert).
4. The safe-machine variant (spurious NEEDS_MORE_INPUT) only stalls until
   the caller closes input; the unsafe-machine livelock is the dangerous
   one and is the default fast path of BrotliDecoderDecompressStream.

## Repro artifacts (lab only)

- corpus/constructs/a2_large_min.br (54B, minimized) — livelocks
  v1.1.0/v1.2.0 when LARGE_WINDOW enabled; clean -17 on v1.2.1.
- corpus/constructs/a2_large.br (83B robust variant).
- Standard-window shapes (a2_nsym1*, a2_overshoot_ctrl, a2_noswitch_ctrl)
  are retained as proof-of-unreachability controls (die -9/-13).
- Full matrix: lanes/glm1/sweep-results.tsv + captures/.
