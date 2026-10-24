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

## Construct A2 — literal switch with NBLTYPESL=1 (REACHABLE, requires LARGE_WINDOW)

**Reachability is the subtle part — three v1.2.0 guards fence off the naive
shapes, and the final working shape needs the large-window code path:**

Guards discovered (all in v1.2.0):
- G1: `meta_block_remaining_len -= i` is UPFRONT per command; the value is
  checked `< 0` in `WriteRingBuffer` (error BLOCK_LENGTH_1, raised on every
  ring-buffer wrap / output flush) and at METABLOCK_DONE (BLOCK_LENGTH_2),
  plus `<= 0 -> metablock ends` after every command's insert/copy.
- G2: MLEN <= 2^24 = BROTLI_BLOCK_SIZE_CAP = initial block_length[0]. So
  attempted literals (sum of inserts) <= MLEN < 2^24+1 while MLEN >= 0 —
  the trigger literal (2^24+1) forces MLEN < 0.
- G3: ring geometry. pos advances 1 per literal AND per copy byte;
  block_length[0] only per literal. At any command start:
  pos0 + bl = 2^24 + sum_copies (mod ring). Trigger needs
  pos0 + bl + 1 <= ring; with ring <= 2^24 (window cap) and the G2 invariant,
  a wrap ALWAYS precedes the trigger (proof by cases k=floor((I+C)/ring)),
  and that wrap's WriteRingBuffer sees the G1 negative MLEN -> clean error.
  Empirically confirmed: every naive shape dies with BLOCK_LENGTH_1/-9.

The escape: `BrotliCalculateRingBufferSize` sizes the ring to
`pow2 >= pos + MLEN` (canny allocation) but CAPS it at `1 << window_bits`.
With **LARGE_WINDOW** enabled (`BrotliDecoderSetParameter(...,
BROTLI_DECODER_PARAM_LARGE_WINDOW, 1)` — public opt-in, e.g. Envoy's brotli
decompressor sets it), the stream can declare window_bits up to 30.
Then a first metablock that leaves pos >= 1 makes
min_size = pos + 2^24 > 2^24, so the ring becomes 2^25 (canny halving
cannot shrink below min_size) — **bigger than the whole 2^24 literal
burn**, so no wrap ever happens, G1 is never observed, and the
(2^24+1)-th literal hits `block_length[0]==0` -> NextLiteralBlock ->
DecodeBlockTypeAndLength -> `max_block_type <= 1` -> FALSE.

Working bitstream (corpus/constructs/a2_large.br, 83 bytes):
- large-window WBITS prefix: 1,000,001,0 + 6-bit wbits=25
  (only decodes when the app enabled LARGE_WINDOW; otherwise -13 error).
- mb1: ISLAST=0, MNIBBLES=00, MLEN=1, ISUNCOMPRESSED=1 (non-last reads
  the bit!), byte-align, one raw 'A' -> pos=1. NB: distance htree symbol
  width becomes 8 bits (large-window dist alphabet = 16+(62<<1) = 140).
- mb2: ISLAST=1, MLEN=2^24 (MNIBBLES code 2, six 0xF nibbles), NBLTYPES
  1/1/1, NPOSTFIX=NDIRECT=0, CMPL=0, NTREES 1/1, simple 1-symbol trees
  (literal sym 0 => 0-bit codes; cmd sym 504 => insert 22594+24b, copy 2;
  dist sym 0), single command with 24-bit insert-extra 16754623
  -> insert = 2^24+1, then 64B zero padding (keeps CheckInputAmount fed).

Old (v1.2.0) behavior: burn 2^24 zero-bit literals (~40ms), then literal
2^24+1: switch FALSE -> UNSAFE machine (the default first path of
BrotliDecoderDecompressStream) discards it -> infinite
CommandInner <-> NextLiteralBlock loop, zero bits consumed, 100% CPU,
NEVER RETURNS (all APIs: one-shot and streaming, all 3 harness modes).
SAFE machine (only if bit reader dry at the switch): permanent spurious
NEEDS_MORE_INPUT.

New (v1.2.1) behavior: same burn, then ERROR_FORMAT_BLOCK_SWITCH (-17)
clean error in ~40ms. Negative control ✓.

Empirical matrix (local pristine builds of v1.2.0/v1.2.1 tags,
range/decodeh/harness.c with --large flag):
```
            --large   --large --stream/--ring   (no --large)
v1.2.0      124 LIVELOCK (100% CPU)            rc=2 -13 (window bits)
v1.2.1      rc=2 code=-17 in 0.04s             rc=2 -13
```

Who is exposed: any embedding that sets LARGE_WINDOW=1 on the decoder
(Envoy brotli decompressor filter does; plain Node zlib / Bun do NOT by
default — verify on the lanes at rung 5). Practical impact: CPU DoS /
event-loop freeze via an 83-byte Content-Encoding: br body; also the
spurious-NEEDS_MORE_INPUT stall variant for the safe machine.

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
  burn is bounded by ring checks. No write primitive is apparent from the
  diff. If ASan fires on A2, it will be something we did not predict —
  capture it.
- The unchecked `meta_block_remaining_len -= i` overshoot itself is caught
  by the G1 guards (BLOCK_LENGTH_1/2) — it is NOT a free OOB.
- Non-large-window variants (a2_nsym1.br etc.) are kept as PROOF-OF-
  UNREACHABILITY controls: stock decoders reject them (-9/-13/etc),
  demonstrating the guards; only a2_large.br triggers.
- Watch the ctrl (1.2.1 asan) run time on A2: it must still burn ~2^24
  literals (~40ms native; slower under ASan) before erroring -17.
