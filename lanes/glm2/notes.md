# brot-glm2 notes (cold-revival)

Lane goal: settle app-level RCE reproduction of CVE-2026-111497 on arm64 host.
C level CLOSED (glm1, fenced). NEVER execute googlesky/Imperva code; our
app.js + our corpus only; loopback; timeout 20 every shell-out.

## Step 1 — STREAMING ORACLE on node 22.23.3 (:8121 vuln) / 22.23.4 (:8125 ctrl)
- range/node/app.js: added GET /health (pid — restart detector), POST
  /decompress-stream — createBrotliDecompress({maxOutputLength:1<<28}) fed
  in 16B pieces, pump semantics: write -> (await drain) -> setImmediate
  yield -> write (per-piece threadpool dispatch, mirrors network-arriving
  chunks; ?chunk=N overrides).
- KEY FINDING: streaming surface EXPOSES e.errno — the -9 (vuln:
  ERR__ERROR_FORMAT_BLOCK_LENGTH_1) vs -17 (ctrl:
  ERR__ERROR_FORMAT_BLOCK_SWITCH) differential is app-visible. The sync
  API hid it (generic "Decompression failed" both). poc0/poc1 produce
  16,760,832 output bytes then error -9/-17 respectively — identical
  output both lanes, no partial-output anomaly.
- Sweep 50 attempts x 111 vectors x 2 lanes = 11,100 reqs
  (lanes/glm2/stream-sweep50.tsv): ZERO crashes (all curl rc=0), ZERO
  hangs, ZERO restarts (pid stable both), ZERO anomalies. Vuln-vs-ctrl
  distributions differ ONLY by 100x -9 <-> 100x -17 (poc0/poc1).
- a2_nsym1*/a2_nsym2/a2_overshoot_ctrl die -9 on BOTH builds (pre-existing
  MLEN<0 proactive-push guard fires before the P1 switch difference —
  consistent with glm1 fencing). a2_large* die -13 WINDOW_BITS (node never
  sets LARGE_WINDOW). poc2/poc3 = Z_BUF_ERROR(-5) both (truncation stall,
  flush at EOF errors cleanly — no infinite NMI accept at app level).
- chunk=1 pass (stream-sweep-chunk1.tsv): a2_nsym2 (2MB) "HANGS" at 20s
  on BOTH lanes — CHARACTERIZED: NOT a livelock; completes in ~27s
  (2M byte-granular threadpool dispatches; 197% CPU while running),
  errors -9. Client-timeout artifact. No vuln/ctrl differential.
- STEP 1 VERDICT: node 22 streaming app surface = NOT REPRODUCED
  (error differential only; no crash/hang/memory anomaly; 50-attempt floor).

## Step 2 — node:24.22.0 (:8124) / node:24.22.1 (:8130 ctrl) — Imperva's pair
(pending)

## Step 3 — express5.3.0+body-parser2.3.0 (:8126 vuln / :8127 ctrl) — pending
## Step 4 — fetch-victim (:8128) + evil-origin (:8129) — pending
