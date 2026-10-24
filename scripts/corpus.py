#!/usr/bin/env python3
"""Seed corpus for CVE-2026-111497 harness sweep.
Shapes derived from fix diff b418fa8 (v1.2.0->v1.2.1): block-type-switch path
that returned BROTLI_FALSE mid-read while the unsafe state machine kept going.
FILE-BASED inputs for OUR decoder rigs only."""
import os
import brotli as _br  # bindings only

def br_compress(data, q=11, win=22):
    try:
        return _br.compress(data, quality=q, lgwin=win)
    except TypeError:
        return _br.compress(data)

OUT = os.path.join(os.path.dirname(__file__), "..", "corpus", "seeds")
os.makedirs(OUT, exist_ok=True)

def emit(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)

emit("empty.br", b"")
emit("onebyte_00.br", b"\x00")
emit("trivial_valid.br", br_compress(b"hello brotli " * 10))
emit("valid_empty.br", br_compress(b""))

s = 0xBADC0DE
def rnd(n):
    global s
    out = bytearray()
    for _ in range(n):
        s = (s * 6364136223846793005 + 1442695040888963407) & (1 << 64) - 1
        out.append((s >> 33) & 0xFF)
    return bytes(out)
for i in range(16):
    emit("garbage_%d.br" % i, rnd(64 + i * 37))

rich = br_compress(b"The quick brown fox jumps over the lazy dog. " * 50)
for cut in (1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 24, 32, 48, 64, 96, 128):
    if cut < len(rich):
        emit("trunc_%d.br" % cut, rich[:cut])

for n in (4, 8, 16, 64):
    emit("prefix8_junk%d.br" % n, rich[:8] + rnd(n))
    emit("prefix4_junk%d.br" % n, rich[:4] + rnd(n))

for pos in range(4, min(21, len(rich))):
    for bit in (0, 3, 7):
        m = bytearray(rich)
        m[pos] ^= (1 << bit)
        emit("flip_%d_%d.br" % (pos, bit), bytes(m))

try:
    lw = br_compress(b"A" * 200000, q=11, win=24)
    emit("bigwindow_valid.br", lw)
    emit("bigwindow_trunc16.br", lw[:16])
except Exception as e:
    print("bigwindow skipped:", e)

two = br_compress(bytes(((i * 6364136223846793005 + 1) >> 24) & 255 for i in range(4096)))
emit("random_payload_valid.br", two)
for cut in (2, 5, 9, 20, 40):
    emit("randpl_trunc%d.br" % cut, two[:cut])
print("seeds:", len(os.listdir(OUT)))
