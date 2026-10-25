# VERDICT — brot-glm2 (rung 7e): APP-LEVEL RCE reproduction, CVE-2026-111497

Extends lanes/glm1/verdict.md (C level CLOSED: 88+ ASan runs zero OOB,
append mechanism arithmetically fenced). This lane built the four app
surfaces the prior lanes never had (streaming createBrotliDecompress
pump, the exact Imperva image pair, express5+body-parser2 inbound,
fetch/undici outbound) and swept OUR corpus against each on our arm64
host — Imperva's proven architecture. Their exact build pair
(node:24.22.0 vuln / node:24.22.1 ctrl) was used for every surface.
NEVER executed googlesky/Imperva code; all lane code ours; loopback +
own containers; timeout 20 every shell-out; npm ci --ignore-scripts
with committed lockfile.

## Per-surface final answer

| surface | verdict | attempts | crash/hang/restart/OOM | what IS observable |
|---|---|---|---|---|
| C level (glm1, closed) | fenced: no OOB write, DoS class only | 88 ASan runs + 100k-byte refeed | zero ASan | -9 vs -17 differential; livelock w/ LARGE_WINDOW |
| node streaming (16B pump, drain-yield semantics) 22.23.3/22.23.4 | **NOT REPRODUCED** | 11,100 (50×111×2) | zero (pid stable, no events) | e.errno surfaces the bug signature: -9 vuln vs -17 ctrl (poc0/poc1, out=16,760,832 identical both) |
| node streaming 24.22.0/24.22.1 (Imperva's exact pair) | **NOT REPRODUCED** | 11,100 (50×111×2) | zero (RestartCount=0, OOMKilled=false, events clean) | same -9↔-17 only; lineage confirmed (v1.2.0-family in 24.22.0, patched in 24.22.1) |
| express@5.3.0 + body-parser@2.3.0 (raw/json/ejson, Content-Encoding: br bodies) 24.22.0/:8126 vs 24.22.1/:8127 | **NOT REPRODUCED** | 33,300 (50×111×3 routes×2) | zero | body-parser 400s with errno echoed: -9 vs -17 (poc0/poc1) — identical on all 3 parser routes |
| fetch()/undici victim fetching OUR evil-origin (chunked 1KB corked delivery, real socket timing) 24.22.0/:8128 vs 24.22.1/:8131 | **NOT REPRODUCED** | 11,100 (50×111×2) | zero (all 3 containers RestartCount=0) | fetch TypeError 'terminated' with cause errno: -9 vs -17 (poc0/poc1) |

## Verified facts this lane adds (beyond glm1)

1. **The bug's error-code differential IS app-visible on every surface.**
   Streaming zlib surfaces e.errno: ERR__ERROR_FORMAT_BLOCK_LENGTH_1
   (-9) on vulnerable builds vs ERR__ERROR_FORMAT_BLOCK_SWITCH (-17) on
   patched — a clean fingerprint (detect/WAF), but NOT memory corruption.
2. **undici (node 24.22.x) does NOT advertise br**: fetch sends
   Accept-Encoding: gzip, deflate — yet it still decompresses
   Content-Encoding: br responses (valid vector returns decompressed
   len; errno differential proves the brotli path). Verified, not assumed.
3. **The async pump never exhibits the googlesky append scenario**: at
   app level, every "hungry" NMI state is resolved by the next write()
   batch or terminated by end()/flush -> Z_BUF_ERROR(-5) truncation error
   on BOTH builds (poc2/poc3: -5 both lanes; byte-count 13/19, 9/15
   flush-timing nondeterminism identical across lanes — not a vuln
   differential).
4. **chunk=1 a2_nsym2 "hang" is dispatch overhead**, not livelock: 2M
   byte-granular threadpool dispatches, ~27s, completes -9, both lanes.
5. a2_nsym*/a2_overshoot shapes die -9 on BOTH builds (pre-existing
   MLEN<0 proactive-push guard, unaffected by the patch); a2_large* die
   -13 WINDOW_BITS (no embedding here sets LARGE_WINDOW) — matching the
   glm1 fencing arithmetic at app level.

## Why Imperva's RCE claim does not reproduce here (honest state)

On their exact image pair, architecture (arm64), and both proven
surfaces (fetch br responses, express/body-parser br bodies), with
real-socket chunked delivery timing, our full corpus + all published
vectors, at the 50-attempt floor: NO crash, NO hang, NO restart, NO
OOM, NO memory read-back anomaly, NO output-byte differential beyond
the -9/-17 error code. Everything observable is consistent with
glm1's conclusion: the b418fa8 flaw yields an error-code differential
and (only via LARGE_WINDOW, which no surface here enables) a CPU
livelock — not memory corruption. If Imperva's marker-file RCE is
genuine, the delta is in components we do not have: their build/harness
(Sysdig noted a weakened/custom build for googlesky), a different
vector, or additional conditions — none reachable with the published
vectors on official images. Verdict: **NOT REPRODUCED on all four
surfaces; NOT INDICATIVE of RCE at app level on official builds.**

Artifacts: lanes/glm2/{stream-sweep50,stream-sweep-24x,express-sweep50,
fetch-sweep50}.tsv, stream-sweep-chunk1.tsv, scripts, notes.md.
