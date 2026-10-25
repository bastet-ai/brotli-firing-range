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

## Step 2 — node:24.22.0 (:8124 vuln) / node:24.22.1 (:8130 ctrl) — Imperva's exact pair
- Services node240-vuln / node240-ctrl (compose, loopback-published, no
  platform pin), same range/node/app.js streaming oracle.
- 50 attempts x 111 vectors x 2 lanes = 11,100 reqs
  (lanes/glm2/stream-sweep-24x.tsv): ZERO crashes, ZERO hangs, ZERO
  restarts (docker inspect: RestartCount=0, OOMKilled=false both),
  docker events: no die/oom/kill/restart. pid stable both.
- Vuln-vs-ctrl differs ONLY by poc0/poc1 -9<->-17 (100 each; identical
  out=16,760,832 both lanes both builds). a2_* identical to step 1.
  poc2/poc3 partial-output byte count varies (13/19, 9/15) — flush-timing
  nondeterminism on truncation, SAME on both lanes (not a differential).
- Lineage note: 24.22.0 shows the vuln signature (-9 at P1-overshoot),
  24.22.1 the patched one (-17 at switch) — oracle validity confirmed
  (v1.2.0-lineage decoder in 24.22.0, patched in 24.22.1).
- STEP 2 VERDICT: NOT REPRODUCED (50-attempt floor met, no crash/hang/
  restart/OOM/memory anomaly on the streaming surface of the exact
  Imperva image pair).

## Step 3 — EXPRESS SURFACE :8126 (24.22.0) / :8127 (24.22.1)
- range/express (OURS): express@5.3.0 + body-parser@2.3.0 exact pins,
  package-lock.json committed (npm install --package-lock-only
  --ignore-scripts), Dockerfile npm ci --ignore-scripts; routes
  /raw (body-parser raw()), /json (body-parser json()), /ejson
  (express 5.3.0 bundled json()); all inflate Content-Encoding: br via
  streaming createBrotliDecompress. Error handler echoes err.errno.
- Verified: valid br body -> 200 ok len=130; poc0 -> 400-ish {errno:-9
  vuln / -17 ctrl} (body-parser catches the zlib stream 'error').
- 50 attempts x 111 vectors x 3 routes x 2 lanes = 33,300 reqs
  (lanes/glm2/express-sweep50.tsv): ZERO crashes/hangs/restarts/OOM
  (RestartCount=0, OOMKilled=false, pid stable both). Vuln-vs-ctrl
  differs ONLY by poc0/poc1 -9<->-17 (identical on all 3 routes).
- STEP 3 VERDICT: NOT REPRODUCED (50-attempt floor; the Imperva inbound
  path express5+body-parser2 with br bodies shows the error-code
  differential and NOTHING else on their exact image pair).

## Step 4 — fetch-victim (:8128 vuln / :8131 ctrl) + evil-origin (:8129)
- OUR evil.js serves corpus vectors as Content-Encoding: br, chunked
  1KB writes + socket cork + 1ms pacing (real-socket delivery timing,
  orchestrator-mandated). victim.js (node 24.22.0/24.22.1) fetches and
  reads via arrayBuffer() -> undici streaming decompression.
- VERIFIED: node 24.22.x fetch does NOT advertise br (Accept-Encoding:
  gzip, deflate only) but DOES decompress br responses (len=130 for
  valid; -9/-17 proves the brotli path).
- 50 attempts x 111 vectors x 2 lanes = 11,100 fetches
  (lanes/glm2/fetch-sweep50.tsv): ZERO crashes/hangs/restarts/OOM (all
  3 containers RestartCount=0, OOMKilled=false). Vuln-vs-ctrl differs
  ONLY by poc0/poc1: fetch TypeError 'terminated', cause errno -9 vs
  -17.
- STEP 4 VERDICT: NOT REPRODUCED (50-attempt floor, chunked real-socket
  delivery matched).

## Step 6 — verdict: lanes/glm2/verdict.md — all four app surfaces
NOT REPRODUCED on the exact Imperva image pair at 50-attempt floor;
only the -9<->-17 error fingerprint is app-visible. Per-step commits
brot2: e3eb54f (step1) 83c803b (step2) + this commit.
