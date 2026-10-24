# brot-glm1 lane notes (durable state — read this first on revival)

Repo ~/brotli-firing-range, lane brot-glm1, BRIEF.md = ladder. `timeout 20`
on shell-outs. Commit+push every result as "brot1: ...". Static audit first,
never execute third-party PoCs, lab decoders only.

## Where we are
- **Rung 1 DONE** (see construct-map.md — read it, it has the full reasoning):
  - Only reachable fix-diff construct is **A2**: literal block switch with
    NBLTYPESL==1, driven to `block_length[0]==0` by an UNCLAMPED 24-extra-bit
    insert length (cmd symbol 504, insert offset 22594, max insert 16799809
    > 2^24 = BROTLI_BLOCK_SIZE_CAP). Old code: `DecodeBlockTypeAndLength`
    returns FALSE for max_block_type<=1; UNSAFE machine (the default fast
    path of BrotliDecoderDecompressStream, decode120.c L2788!) DISCARDS the
    FALSE -> infinite NextLiteralBlock<->CommandInner loop, 0 bits consumed,
    100% CPU, never returns. SAFE machine converts the same FALSE into a
    permanent spurious NEEDS_MORE_INPUT (stream stall / "truncated").
  - A1 (command switch) / A3 (distance switch) mathematically unreachable:
    every command consumes >=2 MLEN, MLEN <= 2^24 => <= 2^23 commands/dist
    reads < 2^24 default block length. Proof in construct-map.md.
  - Constructs B/C (safe-mode mid-switch needs-input) have NO behavioral
    delta in the fix; transactional reads; do not re-litigate.
  - Working hypothesis: this is a CPU-livelock DoS, not OOB. If ASan says
    otherwise on rung 2, trust ASan and re-derive.
- **Bitstreams built**: corpus/constructs/{a2_nsym1.br (76B, primary),
  a2_nsym1_short.br (16B, safe-stall variant), a2_nsym2.br (2MB, 1-bit
  literal codes fallback), a2_noswitch_ctrl.br (insert below cap, no
  trigger)} via scripts/gen_constructs.py (hand-rolled LSB-first bit
  writer; no encoder used, no third-party decoder touched).
  Bit-layout notes: WBITS bit0=0->w16; ISLAST=1; MNIBBLES=00; MLEN-1 16b;
  NBLTYPESL/C/D=1 (1 bit each); NPOSTFIX/NDIRECT 6x0; CMPL=0; NTREES=1;
  simple huff = '01' + NSYM-1(2b) + symbols; literal alphabet 256->7b,
  cmd 704->9b, dist alphabet 64 (16+(24<<1))->5b; cmd symbol 504; insert
  extra 24 bits = 16754624 -> insert 2^24+2; 64B zero padding keeps
  CheckInputAmount fed (0-bit literal codes consume nothing).

## Next (rung 2, blocked on docker images decodeh-asan/-plain/-ctrl)
- Sweep corpus/seeds + corpus/constructs through decodeh-asan
  (`docker run --rm -v corpus:/c IMG /decode /c/x.br`, also --stream and
  --ring modes per harness) — **expect NO ASan hit on seeds** (they're
  truncated/flips, not this construct); a2_nsym1.br should HANG (timeout)
  on vuln builds and error cleanly (-17 ERROR_FORMAT_BLOCK_SWITCH) on ctrl.
  A hang IS the hit for this construct; record it as such.
- If asan reports an actual OOB anywhere, minimize (rung 3) with bisection
  on the .br bytes (scripts to be written; keep grammar-valid otherwise).

## Gotchas learned
- decode120.c = v1.2.0 decode.c dump (regenerate: git show v1.2.0:c/dec/decode.c).
- Host checkout is master (190 commits past v1.2.0, includes b418fa8+).
- kCmdLut init lives in c/dec/prefix.c (runtime init) AND embedded
  prefix_inc.h; insert extra bits go to 24 (offset 22594 = 0x5842).
- Simple huff symbol width = Log2Floor(alphabet_max-1): literal 7b,
  command 9b, distance 5b (alphabet = 16+(24<<1) = 64 at NPOSTFIX=0).
- 0-bit codes confirmed: PreloadSymbol PEEKS 8 bits (no consume);
  ReadPreloadedSymbol DropBits(*bits=0); bulk copier loop is bounded by
  guard_in which never advances when codes are 0-bit => 64B pad keeps
  CheckInputAmount true through the whole 2^24 literal burn.
- CheckInputAmount = next_in < guard_in; guard = last_in - 28
  (BROTLI_FAST_INPUT_SLACK) when avail_in+1 > 28.
- Node/Bun/Envoy lanes live on :8121/:8125/:8122/:8123 — do not hit until
  rung 5, and only with minimized lab repros.

## Log
- 2026-10-24: rung 1 complete, committed (203e964, 00a8dae).
- 2026-10-24: rung1 self-audit verifier passes on all 4 constructs; 0-bit
  literal code + guard_in semantics verified in v1.2.0 source; oracle
  sweep script ready (scripts/oracle_sweep.sh); decodeh images still
  building at last poll.
