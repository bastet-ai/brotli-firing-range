#!/usr/bin/env python3
"""Static self-audit of the hand-built A2 bitstreams: replays the v1.2.0
metablock-header state machine (bit-level, per /tmp/decode120.c paths) over
our own bytes and asserts the exact decoder state at the trigger point.
No decoder is invoked — this is a bit-layout proof for the construct map."""
import sys, os

class BitReader:
    def __init__(self, data):
        self.d = data; self.pos = 0  # bit position, LSB-first
    def read(self, n):
        v = 0
        for i in range(n):
            byte = self.d[(self.pos) >> 3]
            v |= ((byte >> (self.pos & 7)) & 1) << i
            self.pos += 1
        return v

def verify(path, expect_insert_ge=0):
    d = open(path, "rb").read()
    br = BitReader(d)
    log = []
    def chk(name, got, want):
        assert got == want, f"{path}: {name}: got {got}, want {want} (bit {br.pos})"
        log.append(f"{name}={got}")
    # stream header
    w = br.read(1)
    if w == 0:
        wbits = 16
    else:
        n = br.read(3)
        assert n != 0, "reserved WBITS path"
        wbits = 17 + n
    assert wbits == 24, f"wbits {wbits} != 24 (ring must cover the burn)"
    # metablock header
    chk("ISLAST", br.read(1), 1)
    chk("ISLASTEMPTY", br.read(1), 0)
    nib = br.read(2)                                 # MNIBBLES code
    mlen_m1 = 0
    for i in range(nib + 4):
        mlen_m1 |= br.read(4) << (i * 4)            # decode: bits << (i*4)
    mlen = mlen_m1 + 1
    if expect_insert_ge:
        assert mlen >= 1 << 24, f"MLEN {mlen} < 2^24: burn would trip BLOCK_LENGTH_1"
    # NB: no ISUNCOMPRESSED bit — read only for NON-last metablocks
    # NBLTYPES x3 via DecodeVarLenUint8
    for name in ("NBLTYPESL", "NBLTYPESC", "NBLTYPESD"):
        chk(name, br.read(1), 0)                    # 0 -> value 0 -> +1 = 1
    chk("NPOSTFIX", br.read(2), 0)
    chk("NDIRECT-raw", br.read(4), 0)
    chk("CMPL[0]", br.read(2), 0)
    chk("NTREESL-flag", br.read(1), 0)              # -> 1 tree, no cmap
    chk("NTREESD-flag", br.read(1), 0)              # -> 1 tree, no dist cmap
    # htree groups: literal, command, distance
    def simple(alphabet_max):
        chk("huff-simple-flag", br.read(2), 1)
        nsym_m1 = br.read(2)
        mbits = (alphabet_max - 1).bit_length()  # C Log2Floor == bit_length
        syms = [br.read(mbits) for _ in range(nsym_m1 + 1)]
        return syms
    lit_syms = simple(256)
    chk("lit-symbol", lit_syms[0], 0)
    cmd_syms = simple(704)
    if len(cmd_syms) == 2:
        chk("cmd-symbols", sorted(cmd_syms), [32, 504])  # 2-symbol tree, 1-bit codes
    else:
        chk("cmd-symbol", cmd_syms[0], 504)               # single burn cmd
    dist_syms = simple(64)
    chk("dist-symbol", dist_syms[0], 0)
    # command stream: bit 1 -> 504 (burn), 24-bit insert extra, dist 0-bit;
    # bit 0 -> 32 (trigger, insert 4)
    if len(cmd_syms) == 2:
        chk("cmd1-sel", br.read(1), 1)   # bit 1 -> larger symbol 504
    ins_extra = br.read(24)
    insert = 22594 + ins_extra
    copy_len = 2
    if len(cmd_syms) == 2:
        chk("cmd2-sel", br.read(1), 0)  # bit 0 -> symbol 32: insert 4 > bl 3
    if expect_insert_ge:
        # two-command trigger: burn = 2^24-3 literals (MLEN budget exact),
        # then insert-4 command trips block_length[0]=3 -> switch -> FALSE.
        assert insert + 3 == (1 << 24), f"burn insert {insert} != 2^24-3"
        # decoder state at cmd2: block_length[0]=3 < insert 4 -> NextLiteralBlock
        # with num_block_types[0]=1 -> DecodeBlockTypeAndLength returns FALSE.
    remaining_bits = (len(d) * 8) - br.pos
    # decoder state at this point (per v1.2.0):
    state = {
        "num_block_types[0..2]": [1, 1, 1],
        "block_length[0] (BROTLI_BLOCK_SIZE_CAP)": 1 << 24,
        "meta_block_remaining_len (MLEN)": mlen,
        "insert": insert, "copy": copy_len,
        "trailing_zero_bytes": remaining_bits // 8,
    }
    # livelock proof (trigger files): after the burn command, block_length[0]
    # = 2^24 - (2^24-3) = 3; the trigger command's insert (4) exceeds it, so
    # its 4th literal hits NextLiteralBlock with num_block_types[0]==1 ->
    # DecodeBlockTypeAndLength returns FALSE (P1) -> unsafe machine discards
    # it -> infinite NextLiteralBlock <-> CommandInner loop (zero bits read).
    if expect_insert_ge:
        bl_after_burn = (1 << 24) - insert
        assert 1 <= bl_after_burn <= 3, f"bl_after_burn {bl_after_burn} not < 4"
    print(f"OK {os.path.basename(path)}: " + " ".join(log) +
          f" | mlen={mlen} insert={insert} pad_bytes={state['trailing_zero_bytes']}")
    return 0

base = os.path.join(os.path.dirname(__file__), "..", "corpus", "constructs")
rc = 0
for f in sorted(os.listdir(base)):
    if f.startswith("a2_"):
        thr = (1 << 24) + 1 if f.startswith("a2_nsym") else 0
        rc |= verify(os.path.join(base, f), thr)
sys.exit(rc)
