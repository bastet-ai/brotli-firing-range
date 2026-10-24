# brotli-firing-range — CVE-2026-111497 (lab only)

Firing range for **CVE-2026-111497**: memory corruption / RCE via crafted
Brotli-compressed data in affected decoders (Google Brotli < 1.0.10 /
< 1.1.1 / < 1.2.1; Node.js, Bun, Envoy/Istio brotli paths). Disclosure:
patchtheplanet.org/brotli (updated 2026-10-23). Fixed: Brotli 1.2.1
(commit b418fa8 "Detect and report invalid stream earlier"), Node
22.23.4/24.22.1/26.12.1, Bun 1.4.4, Envoy 1.40.0/1.39.3/1.38.6/1.37.8,
Istio 1.29.9/1.30.6/1.31.2.

## Rules of engagement (binding)
- **Lab targets only.** Every decoder here is OURS, in Docker, published
  loopback-only (127.0.0.1). Zero third-party endpoints, ever.
- Patch-diff-driven research: construct analysis from the upstream fix
  diff (b418fa8), not from guessing, and not from executing any
  third-party PoC that may surface publicly. Static audit first, always.
- No secrets in this repo. Credentials stay out of compose files.
- Commit+push every finding as you go; honest negatives are findings too.
- This repo is PRIVATE deliberately (decoder exploit scaffolding).

## Layout (mirrors php-/gitlab-firing-range conventions)
- `range/decodeh/` — C harness: pristine brotli built from tags, vulnerable
  (1.2.0) + patched (1.2.1) as side-by-side ASan/plain builds; file-in /
  decompress / oracle. The split rig: ASan = detection, plain = exploitation.
- `range/node/` — pre-fix Node (22.23.x-1) container decompressing uploaded
  bodies (zlib brotli + internal decoder paths), loopback :8121.
- `range/bun/` — pre-fix Bun container, same shape, :8122.
- `range/envoy/` — pre-fix Envoy with brotli decompressor filter on
  request + response paths, :8123.
- `scripts/` — corpus builder, fuzz drivers, the one-shot harness client.
- `lanes/` — GLM-5.3 lane state (BRIEF + notes; tmux session brot-glm1).

## Targets matrix vs advisory
| path | vulnerable | patched control |
|---|---|---|
| C decoder | brotli 1.2.0 ASan/plain | 1.2.1 ASan |
| Node | node:22.23.3-slim (or last pre-22.23.4) | 22.23.4 |
| Bun | bun 1.4.3 | 1.4.4 |
| Envoy | envoy v1.39.2 + brotli decompressor | v1.39.3 |

Win conditions (in order): deterministic crash under ASan with minimized
repro; write-primitive characterization (gdb, value/length control);
then the exploit ladder (marker-file exec -> shell) — meterpreter-style
delivery only after a primitive is proven, per the standing gate.
