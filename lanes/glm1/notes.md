# brot-glm1 lane notes (durable state — read this first on revival)

Repo ~/brotli-firing-range, lane brot-glm1, BRIEF.md = ladder. `timeout 20`
on shell-outs. Commit+push every result as "brot1: ...". Static audit first,
never execute third-party PoCs, lab decoders only.

## HEADLINE (rung 1 + local rung-2 preview COMPLETE)
**Construct A2 reproduced: 83-byte .br -> vulnerable brotli v1.2.0 livelocks
at 100% CPU forever (never returns, all API shapes); v1.2.1 rejects cleanly
with -17 ERROR_FORMAT_BLOCK_SWITCH in 40ms.** Confirmed on local pristine
builds of both tags with our own harness (NOT yet on the docker rigs —
see BLOCKED below).

The bug: DecodeBlockTypeAndLength returns BROTLI_FALSE for
max_block_type<=1; the UNSAFE state machine (default first path of
BrotliDecoderDecompressStream) DISCARDS the FALSE ->
NextLiteralBlock <-> CommandInner infinite loop, 0 bits consumed.
Fix b418fa8 maps it to ERROR_FORMAT_BLOCK_SWITCH and propagates in
unsafe mode via BROTLI_SAFE_WITH_STATUS.

## CRITICAL reachability facts (do not lose these)
- A2 requires the app to SetParameter(BROTLI_DECODER_PARAM_LARGE_WINDOW,1).
  **Envoy's brotli decompressor sets it; Node zlib/Bun default = off**
  (verify at rung 5). Without it the stream dies -13 at window bits.
- Three v1.2.0 guards make naive shapes impossible (all verified):
  G1 upfront `meta_block_remaining_len -= insert`, checked <0 at every
  ring wrap (BLOCK_LENGTH_1) / metablock end (BLOCK_LENGTH_2), plus <=0
  ends the metablock after each command; G2 MLEN <= 2^24 = bl[0] initial;
  G3 ring = pow2 >= pos+MLEN capped at 1<<window_bits -> wrap always
  precedes trigger with standard windows.
- Escape: LARGE_WINDOW stream (prefix 1,000,001,0 + 6-bit wbits 10..30)
  + first metablock leaving pos>=1 (1-byte uncompressed warmup) ->
  BrotliCalculateRingBufferSize gives ring 2^25 > burn -> no wrap ever
  -> literal 2^24+1 trips the switch while all guards stay unobserved.
- kCmdLut symbol 504 = insert 22594 + 24 extra bits (max insert 16799809
  > 2^24), copy 2, explicit distance. Symbol 32 = insert 4/copy 2.
- Header bit-order gotchas banked: ISUNCOMPRESSED bit ONLY for NON-last
  metablocks; simple-huff symbols are Log2Floor(alpha-1) bits where C
  Log2Floor == bit_length (lit 8, cmd 10, dist 6, dist-large-window 8
  [alphabet 140]); MLEN nibbles shift by 4i; large-window prefix selects
  via 1,000,001,0.
- 0-bit literal codes confirmed real: 1-symbol simple tree = code length 0
  (BrotliBuildSimpleHuffmanTable case 0); bulk copier consumes nothing;
  64B zero pad keeps CheckInputAmount (next_in < guard_in, slack 28B) fed.

## Artifacts
- corpus/constructs/: **a2_large.br (83B, THE repro)**; a2_nsym1.br /
  a2_nsym1_short.br / a2_nsym2.br (non-large shapes = unreachable-proof
  controls, die -9/-13 on stock decoders); a2_overshoot_ctrl.br (dies -9
  = G1 guard demo); a2_noswitch_ctrl.br (burn only, no trigger, clean).
- scripts/gen_constructs.py (builder), scripts/verify_construct.py
  (bit-level replay self-audit), scripts/oracle_sweep.sh (rung 2 sweep,
  needs update: add --large mode + treat rc=124 as HIT), lane docs.
- range/decodeh/harness.c CHANGED: output draining (loop on
  NEEDS_MORE_OUTPUT — A2 produces 16MB before the trigger; without
  draining you get false negatives) + `--large` flag (SetParameter
  LARGE_WINDOW=1, models Envoy). **DECODEH IMAGES MUST BE REBUILT with
  the new harness.c** — old-harness images will false-negative on A2.
  Tell the orchestrator.
- Local pre-validated rigs (host, ours only, no docker): /tmp/decode_v120
  (v1.2.0), /tmp/decode_v121 (v1.2.1), /tmp/decode_dbg_large (instr.);
  worktrees /tmp/b120, /tmp/b121. Matrix: v120 --large[*] = rc124
  livelock; v121 --large[*] = rc2 code -17 fast; no --large = rc2 -13.

## APP-LANE MATRIX (rung 5 preview done — ALL NEGATIVE, source-proven)
- envoy 1.39.2: brotli filter sets ONLY DISABLE_RING_BUFFER_REALLOCATION
  (source/extensions/compression/brotli/decompressor/brotli_decompressor_impl.cc
  @v1.39.2), never LARGE_WINDOW; + MaxInflateRatio=100 bomb protection.
  a2_large -> brotli_error stat, 0-byte body upstream. Envoy pins brotli
  v1.2.0 (repository_locations.bzl) — vulnerable CODE, unreachable STATE.
- node 22.23.3 & ctrl 22.23.4: zlib brotliDecompressSync, no large-window
  param -> "Decompression failed". bun 1.4.3 DecompressionStream("brotli")
  (lane app fixed from "br") -> "brotli decode failed".
- Pre-1.0.3 stale-table "continue" theory DEAD for envoy (pins v1.2.0).
- v1.1.0 tag also livelocks; v1.0.9 errors cleanly (-10).

## Verdict so far (honest)
DoS (CPU livelock / event-loop freeze; plus spurious-NEEDS_MORE_INPUT
stall variant for safe machine when input runs dry at the switch).
No OOB/write primitive visible in this diff. Rung 4 likely N/A unless
ASan surprises. Rung 5: Envoy lane (:8123, brotli request decompressor,
v1.39.2) is the primary real-world target; Node/Bun lanes expected
CLEAN unless they expose LARGE_WINDOW params (check node
zlib brotli options: `params` in brotliDecompress?).

## Next
1. Images rebuild w/ new harness -> docker oracle sweep (constructs +
   seeds x oneshot/stream/ring x asan/plain/ctrl; --large for A2;
   rc=124 = HIT; log lanes/glm1/sweep-results.tsv).
2. Rung 3 DONE (preview): minimized = a2_large_min.br, 54 bytes;
   remaining bits are all semantically required (prefix 12b, warmup
   mb ~36b+1B for pos>=1, mb2 header ~34b, three simple trees 27b,
   24b insert-extra, 35B pad for the 28B guard slack).
3. Rung 5: POST a2_large.br to envoy :8123 (expect hang/timeout),
   node :8121 (expect clean error - window bits), bun :8122, ctrl
   node :8125. Record per-lane verdicts.
4. Rung 6: DoS-vs-RCE verdict row + defensive write-up notes (block
   Content-Encoding: br at ingress or cap decode CPU; patch = upgrade).

## Log
- 2026-10-24: rung 1 committed (203e964, 00a8dae) — construct map +
  naive bitstreams (pre-reachability-proof).
- 2026-10-24: reachability deep-dive: found G1/G2/G3 guards; naive
  shapes all die -9 locally; proved unreachability for standard windows;
  found LARGE_WINDOW + warmup escape; a2_large.br LIVALOCKS v1.2.0
  (all modes) and errors -17 on v1.2.1. Harness fixed (drain + --large).
  Committing. Images need rebuild.
