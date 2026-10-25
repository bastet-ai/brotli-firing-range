# HANDOFF brot-glm1 -> brot-glm2 (24-Oct, lane at 86% ctx)
State: rungs 1-7 complete. Verified facts: -9/-17 differential solid
(all modes, 88+100k-byte runs); ZERO ASan OOB on pristine C decoder
(5 lineages x oneshot/64k/bytes1/refeed); G3 correction (22B two-command
switch works at STANDARD window, poc0 in poc/); append-OOB fenced by
arithmetic (verdict.md has the MLEN_rem inequality); DCHECK off in asan
build; envoy source-proof (DISABLE_RING_BUFFER_REALLOCATION only +
MaxInflateRatio=100, pins v1.2.0); node/bun C-states unreachable via
their exposed params.
UNRESOLVED: Imperva ran code on OFFICIAL node:24.22.0 arm64 via fetch()
+ express5/body-parser2 (standard paths, no debugger) - our app lanes
were the WRONG ORACLE (brotliDecompressSync = one-shot; createBrotli-
Decompress streaming never tested; express never deployed; 7e not run).
googlesky lab = custom harness (asan-driver*.c, node-decode-vulnerable.c
- wrapper-specific, matches Sysdig "weakened build" note). Static reads
only of all third-party repos; NEVER execute googlesky/Imperva code.
See: verdict.md, RESEARCH-2026-10-24.md, sweep2-results.tsv, poc/.
