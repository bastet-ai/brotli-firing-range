# BRIEF brot-glm2 — APP-LEVEL RCE verification (rung 7e): the oracle we never built

Read first: lanes/glm1/HANDOFF.md, verdict.md, RESEARCH-2026-10-24.md.
C level is CLOSED honestly (fenced arithmetic + 88 runs zero ASan). The
OPEN question is app-level: Imperva ran code on the OFFICIAL
node:24.22.0 linux/arm64 image via fetch() br responses AND
express5/body-parser2 br request bodies. Our node oracle used
brotliDecompressSync (one-shot = WRONG PATH) and we never deployed the
streaming/express/fetch surfaces. This lane builds them and settles it.
Our host IS arm64 = their exact proven architecture.

RoE unchanged: loopback only, own containers, payloads from OUR corpus
(poc/, corpus/constructs), NEVER execute googlesky/Imperva code — not
run-poc.sh, not lab/src, not asan-driver*.c (static reads of their .md/
.c text for MECHANISM only; their lab is a custom harness anyway).
Commit brot2: per result. timeout 20 every shell-out. free -g first
(host ~10G avail; brotli + php + glab co-tenants).

## Ladder
1. STREAMING ORACLE on existing node-vuln :8121 (code OURS):
   add /decompress-stream to range/node/app.js using
   createBrotliDecompress fed in small chunks (16B pieces, 'data'
   events) — mirrors real streaming; same for node-ctrl :8125.
   Feed all poc/ + constructs vectors. Record: errors, exits, hangs.
   (Their advisory says the append happens in BrotliDecoderDecompressStream
   continuation — node's async zlib uses exactly that; Sync may too but
   the CONTINUATION after NEEDS_MORE_INPUT is the app-visible difference:
   async keeps calling with more input where our C harness stopped.)
   KEY: our C harness fed until EOF then STOPPED; an async node pump
   keeps pushing bytes into a hungry state across write() calls —
   replicate pump semantics EXACTLY (write, wait drain, write again).
2. node:24.22.0 lane (:8124) + node:24.22.1 ctrl (:8130): official
   images (already manifest-verify existence), same app.js, same sweep.
   Their exact image pair.
3. EXPRESS SURFACE (:8126): minimal app (ours, npm express@5 +
   body-parser@2 default json()+raw() with inflate) on node 24.22.0;
   POST vectors Content-Encoding: br. Ctrl lane on 24.22.1 (:8127).
   Imperva tested express 5.0.0/5.3.0 + body-parser 2.0.1/2.3.0 — pin
   5.3.0/2.3.0 first (latest they used), 5.0.0/2.0.1 if no signal.
4. FETCH-VICTIM LANE (:8128 victim + :8129 evil-origin, ours): victim
   app = node 24.22.0 doing fetch('http://127.0.0.1:8129/payload.br')
   and reading the response (default undici decompresses br). evil-
   origin serves our vectors. This is the outbound vector; trigger via
   a simple POST /check-url endpoint on victim so the sweep controls
   timing. Note: fetch advertises br by default — verify, don't assume.
5. CRITERIA (per Imperva minus their code): success = child process
   exit/crash on vector that DOES NOT crash on ctrl build, or memory
   read-back anomalies, or their marker-style side effect via our own
   benign marker (a route writing /tmp/marker in the VICTIM app proves
   only that the app wrote it — real RCE evidence = crash signatures/
   sanitizer/known-address clobber, NOT a self-marker; keep honest).
   ASan builds of node are NOT available (official images) -> crash
   differential + core dumps (ulimit -c, container /var/crash or
   ABRT-less: use core_pattern to mounted dir) + gdb on cores (static,
   post-mortem: inspect fault address vs brotli state).
6. VERDICT UPDATE: verdict.md rewrite — final honest answer per surface
   (C fenced / node streaming / express / fetch): reproduced /
   not-reproduced-with-attempts-N / indeterminate, with Sysdig's base
   rate ("execution took multiple attempts") in mind: run at least 50
   attempts per surface-vector pair before claiming negative.
7. If reproduced: STOP at crash+core analysis (primitive characterization
   per standing gate). Do NOT build an exploit chain in this lane.

## Ops
tmux lane brot-glm2; small turns; notes lanes/glm2/notes.md cold-revival;
new compose services: loopback-published, exact image pins, no platform
pinning; npm install ONLY express/body-parser at pins in a build context
we author (supply-chain: exact versions, package-lock committed, no
postinstall surprises: use npm ci --ignore-scripts).
