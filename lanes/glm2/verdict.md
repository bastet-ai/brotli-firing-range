# FINAL VERDICT — CVE-2026-111497 app-level RCE reproduction (brot-glm2, rung 7e)

Extends lanes/glm1/verdict.md. All lane code OURS; payloads OUR corpus +
published vectors only (static reads); loopback + own containers; NEVER
executed googlesky/Imperva code; timeout 20 every shell-out; express deps
pinned with committed lockfile, npm ci --ignore-scripts. Host: arm64 —
Imperva's proven architecture.

## Per-surface table

| surface | attempts | crashes/hangs/restarts/OOM/segfaults | differential observed | verdict |
|---|---|---|---|---|
| C level (glm1, closed) | 88 ASan runs + 100k-byte refeed + 339-run sweep | zero ASan reports | -9 vs -17; LARGE_WINDOW livelock | fenced: no OOB write; DoS class only |
| node streaming 22.23.3/22.23.4 (:8121/:8125) — 16B drain-yield pump | 11,100 (50×111×2) | ZERO (pid stable) | e.errno: -9 vuln vs -17 ctrl (poc0/poc1) | **NOT REPRODUCED** |
| node streaming 24.22.0/24.22.1 (:8124/:8130) — Imperva's exact image pair | 11,100 (50×111×2) | ZERO (RestartCount=0, OOMKilled=false, events clean, dmesg/journal: no segfault) | same -9↔-17 only; identical 16,760,832B output both builds | **NOT REPRODUCED** |
| express@5.3.0 + body-parser@2.3.0 (:8126/:8127) — raw()/json()/bundled ejson, Content-Encoding: br bodies | 33,300 (50×111×3 routes×2) | ZERO | body-parser 400 with errno -9 vs -17, identical on all 3 routes | **NOT REPRODUCED** |
| fetch()/undici victim (:8128 vuln 24.22.0 / :8131 ctrl 24.22.1) ← evil-origin (:8129, chunked 1KB corked writes) | 11,100 (50×111×2) | ZERO (all 3 containers RestartCount=0, no core dumps, no apport hits) | fetch TypeError 'terminated', cause errno -9 vs -17 | **NOT REPRODUCED** |

Total: ~66,700 app-level requests at the 50-attempt floor, all four
surfaces live differential oracle (the vectors demonstrably bite: both
error signatures present on every lane).

## The googlesky arithmetic fence (why the append-OOB cannot fire)

The claimed primitive appends each new input byte into the 8-byte
s->buffer linearly, requiring a never-completing P1-switch NEEDS_MORE_
INPUT lie with MLEN >= 0 at every intervening proactive output push.
That is arithmetically impossible: at the switch, MLEN_rem = 2^24 −
sum_inserts − sum_copies = bl − sum_copies, while the trigger command
needs insert >= bl + 1, so MLEN_rem <= bl − 2 < insert — WriteRingBuffer
fires with MLEN < 0 and errors -9, sending the decoder terminal (error
code < 0 short-circuits all later calls). The app-level observations
confirm exactly this: every "hungry" streaming state is resolved by the
next write() or terminated by end()/flush (Z_BUF_ERROR on BOTH builds
for truncated vectors) — the unbounded-append condition never arises on
any surface, in any feeding mode, at any chunk size (including byte-
at-a-time, characterized to completion).

## Why the Imperva RCE result does not reproduce (matched conditions)

Matched: their exact official image pair (node:24.22.0 /
node:24.22.1), linux/arm64, both of their proven surfaces (fetch() br
responses; express5/body-parser2 br request bodies), exact pinned
express 5.3.0 / body-parser 2.3.0, default paths (no debugger, no
LARGE_WINDOW), real-socket delivery timing (chunked transfer, corked
1KB writes on the evil-origin), our full corpus including all published
vectors (poc0-poc3, a2_*), 50 attempts per vector per lane, continuous
restart/OOM/segfault watch (RestartCount, docker events, dmesg/journal).
Observed: zero crashes, zero true hangs, zero restarts, zero OOM, zero
segfaults, zero core dumps, zero memory read-back anomalies, and an
output-byte differential of exactly nothing beyond the -9 (vuln) vs -17
(patched) error code. If the marker-file RCE is genuine, the delta is in
what we deliberately do not have: their custom/weakened harness or build
(Sysdig's own note on the googlesky lab), an unpublished vector, or
environmental conditions absent from official images. On official
builds with the published vectors, this bug is an error-code
differential and (only with LARGE_WINDOW enabled, which none of these
surfaces do) a CPU livelock — NOT memory corruption.

## Defensive bottom line (for the wiki)

1. Patch: brotli >= 1.2.1 (all embeddings: node 24.22.1 / 22.23.4 pins
   fix it; envoy pins vulnerable v1.2.0 at 1.39.2 — bump). Purely a
   correctness/DoS patch: fix turns a silent FALSE-lie into -17.
2. Detect: the bug fingerprints cleanly at app level — vulnerable
   builds return error errno -9 (ERR__ERROR_FORMAT_BLOCK_LENGTH_1) on
   block-switch-shaped streams where patched builds return -17
   (ERR__ERROR_FORMAT_BLOCK_SWITCH). WAFs/proxies can pre-validate
   Content-Encoding: br bodies against a patched decoder.
3. Deny: LARGE_WINDOW decoding (the livelock path) — no mainstream
   embedding enables it; keep it that way; cap decompression CPU/ratio
   (envoy's 100x bomb ratio model) for the copy.
4. Threat-model honestly: no reproduction exists (C or app level, ours
   or the vectors' authors') of anything beyond DoS/error differential
   on pristine builds; RCE claims traced to custom weakened harnesses
   should not drive panic patching — the patch is still warranted
   (error-correctness + the -17 fingerprint enables detection).

Artifacts: lanes/glm2/{notes.md, stream-sweep50,stream-sweep-24x,
express-sweep50,fetch-sweep50,stream-sweep-chunk1}.tsv + sweep scripts;
range/{node/app.js, express/, fetch-lane/}; docker-compose.yml services.
Commits: e3eb54f step1, 83c803b step2, fc5ba34 step3, 69fcb90 step4, this commit FINAL.
