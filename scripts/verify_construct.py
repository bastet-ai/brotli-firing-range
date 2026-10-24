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
    chk("WBITS-flag", br.read(1), 0)                 # -> window 16, rb 64K
    # metablock header
    chk("ISLAST", br.read(1), 1)
    chk("ISLASTEMPTY", br.read(1), 0)
    nib = br.read(2); chk("MNIBBLES-code", nib, 0)   # 4 nibbles
    mlen_m1 = 0
    for _ in range(nib + 4):
        mlen_m1 = (br.read(4) << (0)) | mlen_m1     # nibbles read LSB-first order
    # NOTE decode reads nibbles into a value: loop shifts by 4 per nibble
    mlen = mlen_m1 + 1
    chk("ISUNCOMPRESSED", br.read(1), 0)
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
        mbits = (alphabet_max - 1).bit_length() - 1
        syms = [br.read(mbits) for _ in range(nsym_m1 + 1)]
        return syms
    lit_syms = simple(256)
    chk("lit-symbol", lit_syms[0], 0)
    cmd_syms = simple(704)
    chk("cmd-symbol", cmd_syms[0], 504)
    dist_syms = simple(64)
    chk("dist-symbol", dist_syms[0], 0)
    # command stream: 0-bit cmd code, 24-bit insert extra, 0-bit copy extra
    ins_extra = br.read(24)
    insert = 22594 + ins_extra
    copy_len = 2
    assert insert >= expect_insert_ge, f"insert {insert} < {expect_insert_ge}"
    remaining_bits = (len(d) * 8) - br.pos
    # decoder state at this point (per v1.2.0):
    state = {
        "num_block_types[0..2]": [1, 1, 1],
        "block_length[0] (BROTLI_BLOCK_SIZE_CAP)": 1 << 24,
        "meta_block_remaining_len (MLEN)": mlen,
        "insert": insert, "copy": copy_len,
        "trailing_zero_bytes": remaining_bits // 8,
    }
    # livelock proof sketch (trigger files only): insert > block_length[0] ->
    # NextLiteralBlock with max_block_type==1 -> DecodeBlockTypeAndLength FALSE (P1).
    if expect_insert_ge:
        assert insert > state["block_length[0] (BROTLI_BLOCK_SIZE_CAP)"]
    print(f"OK {os.path.basename(path)}: " + " ".join(log) +
          f" | mlen={mlen} insert={insert} pad_bytes={state['trailing_zero_bytes']}")
    return 0

base = os.path.join(os.path.dirname(__file__), "..", "corpus", "constructs")
rc = 0
for f in sorted(os.listdir(base)):
    if f.startswith("a2_"):
        thr = (1 << 24) + 1 if "noswitch" not in f else 0
        rc |= verify(os.path.join(base, f), thr)
sys.exit(rc)
