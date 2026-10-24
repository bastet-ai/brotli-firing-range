# Rung 1 — Fix-diff construct map (b418fa8, v1.2.0 -> v1.2.1)

Anchored in the actual v1.2.0 source (`git show v1.2.0:c/dec/decode.c`,
referenced below by line numbers from `/tmp/decode120.c`, regenerable via
`git show v1.2.0:c/dec/decode.c > /tmp/decode120.c`).

## What the fix actually changes

1. `DecodeBlockTypeAndLength` (L1179) returns `BROTLI_BOOL`; only FALSE paths:
   - **P1**: `max_block_type <= 1` -> FALSE (L1189) — reached in BOTH safe
     and unsafe mode, unconditionally.
   - **P2**: safe mode, `SafeReadSymbol(type_tree)` fails (needs input) ->
     FALSE, **memento NOT restored** (but `SafeReadSymbol`/`BrotliSafeReadBits`
     are transactional, so no desync).
   - **P3**: safe mode, `SafeReadBlockLength` fails -> substate reset to
     NONE, memento restored, FALSE (transactional, correct retry).
2. Callers:
   - **Unsafe (non-Safe) machine** (`ProcessCommandsInternal(0,...)` — the
     FAST path that `BrotliDecoderDecompressStream` runs FIRST whenever the
     bit reader has input, L2788): `BROTLI_SAFE` macro (L1943) calls
     `METHOD` and **discards the return value**. Every FALSE from P1/P2/P3
     is silently treated as success.
   - **Safe machine** (fallback when unsafe returns NEEDS_MORE_INPUT):
     `BROTLI_SAFE` maps FALSE -> `BROTLI_DECODER_NEEDS_MORE_INPUT` + state
     save. For P2/P3 that is correct. For P1 it is a **lie**: the stream
     needs nothing; the decoder demands input forever.
3. Fix renames the trio to return `BrotliDecoderErrorCode`, maps P1 to new
   `ERROR_FORMAT_BLOCK_SWITCH` (-17), P2/P3 to NEEDS_MORE_INPUT, and swaps
   `BROTLI_SAFE` -> `BROTLI_SAFE_WITH_STATUS` at the three switch call
   sites so **unsafe mode propagates failure** too.
4. Plus a debug-only `BROTLI_DCHECK(meta_block_remaining_len <= 1<<24)`
   after metablock-length decode, and the -17 error code added to decode.h.

## When do the switches even fire? (reachability math)

All three switches fire only on `block_length[tree]==0`. Per metablock,
`BrotliDecoderStateMetablockBegin` resets `block_length[] = 1<<24`
(BROTLI_BLOCK_SIZE_CAP) and `num_block_types[] = 1` (state.c L114-119).
Switch state (type/length) is only stream-read when NBLTYPES >= 2. So with
`num_block_types[tree] == 1` (the P1 precondition) we need the default
`block_length = 1<<24` to be *consumed to zero* within one metablock:

- **tree 1 (commands)**: one decrement per command (ReadCommandInternal).
  Every command consumes >= 2 from `meta_block_remaining_len` (copy_len
  offset min = 2; insert >= 0; both subtracted, and `meta_block_remaining_
  len <= 0` ends the metablock after each command). MLEN <= 2^24 =>
  commands <= 2^23 < 2^24. **A1 UNREACHABLE.**
- **tree 2 (distances)**: one decrement per distance read, and a distance
  read requires a command (>= 2 MLEN each). Distances <= commands <= 2^23.
  **A3 UNREACHABLE.** (The `++block_length[2]` at L1867 is only the
  safe-mode retry compensation, net zero.)
- **tree 0 (literals)**: one decrement **per literal**, but `i` (insert
  length) is **NOT clamped** to `meta_block_remaining_len` (L1998-2004:
  unchecked `meta_block_remaining_len -= i`, can go negative), and the
  insert loop (CommandInner) has **no per-literal MLEN check** — it only
  stops on block_length[0]==0, ringbuffer wrap, or i exhausted. Insert
  codes go up to offset 22594 with **24 extra bits** (kCmdLut row
  `{0x18, 0x00, -1, 0x00, 0x5842, 0x0002}`, symbol **504**), i.e. max
  insert = 22594 + 2^24 - 1 = 16799809 > 2^24. **A2 REACHABLE.**

## Construct A2 (the one that matters) — literal switch with NBLTYPESL=1

Shape (single metablock, hand-built bitstream, see scripts/gen_constructs.py):

- WBITS=16 (bit 0); ISLAST=1, ISLASTEMPTY=0, MNIBBLES=0b00 (4 nibbles),
  MLEN-1 = tiny (MLEN can even be 1 — the overshoot is unchecked);
  ISUNCOMPRESSED=0.
- NBLTYPESL = NBLTYPESC = NBLTYPESD = 1 (one '0' bit each, so **no block
  type/count codes exist** => `max_block_type = 1` => P1).
- NPOSTFIX=0, NDIRECT=0 (6 zero bits), CMPL=0, NTREESL=1 (no cmap), simple
  1-symbol literal htree => literal codes are **0 bits** (no bit-reader
  pressure for 2^24 literals), simple 1-symbol command tree with symbol
  504, simple 1-symbol distance tree.
- Command: symbol 504 (0-bit code) + 24-bit insert-extra V with
  22594 + V > 2^24 (V >= 16754623; we use V = 16754624 => insert = 2^24+2);
  copy extra = 0 bits.
- Trailing zero padding (>= ~32B) so `CheckInputAmount` never fails and the
  unsafe machine never yields to the safe one.

Old (v1.2.0) behavior on A2:
1. CommandInner burns insert literals against `block_length[0]=2^24`
   (ringbuffer wraps ~256 times @ 64KB window; ~2^24 fast bulk iterations,
   well under a second).
2. `block_length[0]==0` -> `goto NextLiteralBlock` ->
   `DecodeLiteralBlockSwitch` -> P1 FALSE.
3. **Unsafe machine**: FALSE discarded -> `goto CommandInner` ->
   `block_length[0]==0` -> `goto NextLiteralBlock` -> ... **infinite loop,
   zero bits consumed, 100% CPU, never returns.** This is inside
   `ProcessCommands`, which `BrotliDecoderDecompressStream` tries FIRST
   (L2788), so **both one-shot and streaming APIs livelock** while the bit
   reader still has buffered input.
4. **Safe machine** (only if input is exhausted at the switch): permanent
   spurious `BROTLI_DECODER_NEEDS_MORE_INPUT` — stream never completes,
   never errors until the app closes input ("truncated"-style error).

New (v1.2.1) behavior: `ERROR_FORMAT_BLOCK_SWITCH` (-17) after the same
2^24 literal burn => clean error. This is the negative-control oracle.

Sub-variants to emit:
- `a2_nsym1.br` — 0-bit literal codes (primary, ~25 bytes).
- `a2_nsym2.br` — 2-symbol literal tree (1-bit codes) in case 1-symbol
  trees are rejected by some builds; needs ~2MB padding because each
  literal consumes 1 bit.
- `a2_nsym1_short.br` — same as primary but minimal padding: proves the
  safe-mode spurious-NEEDS_MORE_INPUT stall variant.

## Constructs B (P2) and C (P3) — no behavioral delta, documented for honesty

Safe-mode mid-switch "needs more input": old FALSE->NEEDS_MORE_INPUT with
state save; resume re-enters the same switch site (COMMAND_BEGIN /
COMMAND_INNER / COMMAND_POST_DECODE_LITERALS are re-checked and the switch
re-attempted first). Reads are transactional, ringbuffer (`block_type_rb`)
untouched on failure. v1.2.1 is byte-for-byte the same behavior with an
explicit status code. **Not a bug, not a construct** — recorded so nobody
re-litigates it later.

## Honesty notes / open questions for rung 2-4

- This construct is a **CPU livelock / DoS**, not an OOB write: the livelock
  loop (`NextLiteralBlock <-> CommandInner`) writes nothing; the literal
  overshoot is bounded by ringbuffer_size checks. No write primitive is
  apparent from the diff. If ASan fires on A2, it will be something we did
  not predict — capture it.
- The unchecked `meta_block_remaining_len -= i` overshoot itself predates
  and survives the fix (1.2.1 still allows it); the added DCHECK only
  asserts the *header* value <= 2^24, which MLEN satisfies by construction.
- Watch the ctrl (1.2.1 asan) run time on A2: it must still burn ~2^24
  literals before erroring. If that's slow under ASan, that's expected;
  give it a generous timeout but it should finish << 1s.
