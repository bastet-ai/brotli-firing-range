# BRIEF brot-glm1 — CVE-2026-111497 decoder ladder (GLM-5.3)

Repo: ~/brotli-firing-range (PRIVATE). tmux lane: brot-glm1.
Read README.md first (RoE binding: loopback lab only, patch-diff-driven,
never execute third-party PoCs — static audit first).
Commit+push every result as "brot1: ...". timeout 20 on shell-outs.
free -g before anything heavy (host has gitlab-QEMU + php lanes co-tenant).

## Ground truth already established (do not redo)
- Fix = upstream brotli b418fa8 (v1.2.0 -> v1.2.1): DecodeBlockTypeAndLength
  and block-switch path reworked from BROTLI_BOOL to error codes; old code
  returned NEEDS_MORE_INPUT-like false states that callers of the UNSAFE
  (non-Safe) state machine treated as success => decoder continues with
  partially-initialized huffman/block-type state. Read the full diff:
  `cd ~/brotli-src && git show b418fa8` (clone is at ~/brotli-src; also
  inside every decodeh image at /brotli).
- Affected surface per advisory: Node (fixed 22.23.4/24.22.1/26.12.1),
  Bun 1.4.4, Envoy 1.40.0/1.39.3/1.38.6/1.37.8, Istio 1.29.9/1.30.6/1.31.2.
- Range live after compose up: node-vuln :8121 (22.23.3), node-ctrl :8125,
  bun-vuln :8122 (1.4.3), envoy-vuln :8123 (1.39.2, brotli REQUEST
  decompressor ON), decodeh rigs (v1.2.0 asan/plain + v1.2.1 asan ctrl).

## Ladder
1. FIX-DIFF CONSTRUCT MAP: from b418fa8, enumerate the exact malformed
   stream shapes that flip old-code behavior (block-type switch symbol
   read failing mid-stream, block_length read fail + memento restore
   path, ring-buffer state after failed switch). For each: a hand-built
   .br bitstream (scripts/corpus.py — brotli stream grammar: WBITS,
   huffman code descriptor, then the failing construct). Write them out.
2. ORACLE SWEEP: feed every corpus entry through decodeh-asan (docker run
   --rm -v corpus:/c img /decode /c/x.br and --stream/--ring modes).
   ASan report = hit. Same inputs through decodeh-ctrl (1.2.1 asan) MUST
   be clean = negative control proving it's THIS bug.
3. MINIMIZE: crash input ->二分 drop bytes -> smallest repro. Commit
   repros + stack to lanes/glm1/.
4. PRIMITIVE CHARACTERIZATION (only if step 2-3 produce a real OOB):
   gdb on decodeh plain build: is the write value/length attacker-
   controlled (huffman table state / block_length)? Document exactly
   what bytes land where. Gate: no exploit coding until a primitive
   is demonstrated.
5. LANE CONFIRM: crash the Node :8121 / Bun :8122 / Envoy :8123 lanes
   with the minimized repro (HTTP POST body). node-ctrl :8125 clean =
   control. Document which embedded copies are affected.
6. DoS-vs-RCE honest verdict row + notes for the disclosure-adjacent
   defensive write-up (what to block: Content-Encoding: br ingress).

HARD RULES: no external targets; corpus never touches a non-lab decoder;
if a phase is stuck 45min, log + rotate; small turns (pi wall + Venice
stream limits); notes.md is durable state — write it as if you'll be
revived from it cold.
