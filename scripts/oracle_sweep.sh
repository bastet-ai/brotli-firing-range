#!/bin/bash
# Oracle sweep: corpus (seeds + constructs) x modes x rigs.
# HIT for this bug = exit 124 (timeout: livelock) on vuln, clean error on ctrl.
# ASan abort = separate class of hit; capture output.
set -u
CORPUS="$(dirname "$0")/../corpus"
LOG="lanes/glm1/sweep-results.tsv"
VULN_IMG=brotli-firing-range-decodeh-asan
CTRL_IMG=brotli-firing-range-decodeh-ctrl
mkdir -p "$(dirname "$0")/../lanes/glm1/captures"
CAP="$(dirname "$0")/../lanes/glm1/captures"
printf "file\tmode\trig\texit\ttime\tnote\n" > "$LOG"

run_one() { # $1 img $2 mode $3 file $4 extra-args
  local img="$1" mode="$2" f="$3" extra="${4:-}" tag m arg t0 rc ms
  tag=$(basename "$img" | sed 's/brotli-firing-range-//')
  [ -s "$f" ] || return 0
  m="oneshot"; arg=""
  [ "$mode" = stream ] && { m="stream"; arg="--stream"; }
  [ "$mode" = ring ]   && { m="ring";   arg="--ring"; }
  arg="$arg $extra"
  t0=$(date +%s%N)
  timeout 20 docker run --rm -v "$CORPUS:/c" "$img" /decode $arg "/c/$(basename "$f")" \
    > "$CAP/$(basename "$f").$m.$tag.out" 2>&1
  rc=$?
  ms=$(( ($(date +%s%N) - t0) / 1000000 ))
  local note=""
  [ $rc -eq 124 ] && note="TIMEOUT-LIVELOCK"
  [ $rc -eq 1 ] && note="ASAN-ABORT"
  grep -q "ERROR: AddressSanitizer" "$CAP/$(basename "$f").$m.$tag.out" && note="ASAN-REPORT"
  grep -q "code=-17" "$CAP/$(basename "$f").$m.$tag.out" && note="BLOCK_SWITCH_-17"
  printf "%s\t%s\t%s\t%s\t%sms\t%s\n" "$(basename "$f")" "$m" "$tag" "$rc" "$ms" "$note" >> "$LOG"
  echo "$(basename "$f") $m $tag rc=$rc $ms ${note}"
}

# constructs first (a2_large* need --large; others prove unreachability)
for f in "$CORPUS"/constructs/*.br; do
  case "$(basename "$f")" in
    a2_large*) extra="--large" ;;
    *) extra="" ;;
  esac
  for mode in oneshot stream ring; do
    run_one "$VULN_IMG" "$mode" "$f" "$extra"
    run_one "$CTRL_IMG" "$mode" "$f" "$extra"
  done
done
# then the 100 seeds, vuln rig only unless something fires
for f in "$CORPUS"/seeds/*.br; do
  for mode in oneshot stream ring; do
    run_one "$VULN_IMG" "$mode" "$f"
  done
done
echo "---- summary ----"
column -t -s$'\t' "$LOG" | grep -v "rc=.*0ms" | head -50
