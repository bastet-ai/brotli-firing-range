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

---

# Rung 7 (RESEARCH-2026-10-24) — sweep-v2 results: SUPERSEDES nothing, EXTENDS with corrections

## What the rollup got right (confirmed empirically)
- **The illegal switch IS reachable in 22 bytes on STANDARD windows.** The
  published vectors (hypnguyen1209 poc0/poc1, static-read; bytes only, never
  executed their code) hit DecodeBlockTypeAndLength P1 on the literal tree
  via: mb1 = 3-byte uncompressed warmup (pos=3) -> mb2: MLEN=2^24,
  burn-command insert 2^24-3 (MLEN stays 3 >= 0 through all ring wraps),
  copy 2 -> MLEN=1, trigger insert 4 > bl[0]=3 -> literal #4 trips
  NextLiteralBlock with NBLTYPESL=1 -> P1.
  **This CORRECTS my rung-1 G3 "unreachability" proof: the identity I used
  (pos0 + bl == 2^24 + sum_copies mod ring) is wrong when ring | 2^24
  because the 2^24 term vanishes mod ring — pos wraps reset the lockstep,
  so pos0 + bl collapses to just sum_copies (tiny). The two-command shape
  works on ANY window >= 64KB.** (My a2_large LARGE_WINDOW requirement was
  an artifact of that algebra error; the standard-window a2_nsym1 shape
  also triggers — it was already in the corpus, dieing -9/-17.)
- **Differential oracle (the rollup's -9 vs -17): CONFIRMED on pristine
  builds AND docker rigs, across ALL feeding modes** (oneshot, stream64k,
  bytes1, bytes1+refeed, chunk4): vuln (v1.1.0, v1.2.0) = -9
  BLOCK_LENGTH_1; ctrl (v1.2.1) = -17 BLOCK_SWITCH. The vuln decoder
  ignores the failed switch, returns a spurious NEEDS_MORE_INPUT, the
  proactive output push then sees MLEN<0 (the trigger command's upfront
  insert overshoot) and errors -9. Patched errors -17 at the switch itself.

## What the rollup got wrong (our tiebreaker answer)
- **NO out-of-bounds write occurs — on pristine brotli, none of the
  published vectors nor any of ours produces an ASan report**, under:
  - 88 docker asan/ctrl runs x {oneshot, bytes1, bytes1+refeed=300,
    chunk4} (sweep2-results.tsv, captures2/)
  - local pristine v1.1.0+ASan and v1.2.0+ASan, including feeding
    100,000 synthetic bytes past EOF to the "hungry" states
  - The googlesky "append each new input byte into s->buffer.u8[8]
    unboundedly" mechanism is UNREACHABLE: the append loop (L2444-55)
    requires a never-completing read transaction, i.e. the P1-switch
    NMI-lie, with MLEN >= 0 at every intervening proactive push
    (WriteRingBuffer checks meta_block_remaining_len < 0 -> -9 and the
    decoder goes terminal: error_code < 0 short-circuits all later
    calls). MLEN >= 0 at P1 is arithmetically impossible:
    MLEN_rem = 2^24 - sum_inserts - sum_copies = bl - sum_copies, and
    the trigger needs insert >= bl + 1, so MLEN_rem <= bl - 2 < bl + 1
    <= insert — the push fires with MLEN < 0 before any unbounded append.
  - P1 on the command/distance trees is unreachable (NBLTYPES=1 means no
    stream-controlled block lengths; block_length[1]/[2] burn requires
    2^24 copies but MLEN budget allows <= 2^23).
  - The void-continue fall-through after the DISTANCE switch (which DOES
    continue into ReadDistance in unsafe mode) cannot be reached for the
    same block-length reason.
- poc2/poc3 ("hungry" variants) are merely TRUNCATED UNCOMPRESSED
  metablocks (state 11, CopyUncompressedBlockToOutput consuming fed bytes
  as ring data, NMI forever, MLEN large) — a plain truncation stall, not
  the switch; they accept unlimited input without erroring on BOTH vuln
  and ctrl (no differential memory behavior).
- Node app-level (zlib.brotliDecompressSync, lanes :8121/:8125): generic
  "Decompression failed"/"unexpected end of file" on BOTH 22.23.3 and
  22.23.4 — no crash, no hang, no observable differential (sync API does
  not surface the error code).
- DCHECK status (7a/7g): BROTLI_DCHECK(x) is assert(x) ONLY under
  BROTLI_DEBUG/BROTLI_ENABLE_LOG; the asan image's flags.make has neither
  BROTLI_DEBUG nor NDEBUG — DCHECK is a NO-OP in our rigs, so no masking
  and no -DNDEBUG rebuild was needed. Verified in-image.
- The Imperva "marker file" RCE claim is NOT reproducible at the C-decoder
  level with the published vectors; if their result is genuine it must
  involve additional components (Node zlib wrapper behavior, build flags,
  or a different code path) — we could not confirm it and found static
  arithmetic reasons (above) why the buffer-append route cannot fire.

## Updated verdict row (7f)
| claim | verdict |
|---|---|
| OOB write via s->buffer.u8 append (googlesky mechanism) | NOT REPRODUCIBLE; arithmetically fenced (MLEN-push invariant) |
| OOB via stale-state continue (hypnguyen README mechanism) | NOT REPRODUCIBLE on pristine builds (88 ASan runs clean); the continue paths that exist are fenced by the same invariant |
| Differential -9 (vuln) vs -17 (patched) | CONFIRMED, all feeding modes, both v1.1.0 and v1.2.0 lineages — this IS the bug's observable signature |
| Impact on pristine brotli | DoS class only: one-shot/unsafe livelock (100% CPU forever, requires >= 29B input slack) or spurious NEEDS_MORE_INPUT stream stall; error-code differential as above |
