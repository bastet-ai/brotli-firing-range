#!/usr/bin/env bash
# brot-glm2 step 1: streaming oracle sweep (OUR app.js, OUR corpus).
# Usage: stream-sweep.sh VULNPORT CTRLPORT OUT.tsv [attempts]
set -u
V=${1:-8121}; C=${2:-8125}; OUT=${3:-/dev/stdout}; N=${4:-1}
VEC="corpus/constructs/poc0.br corpus/constructs/poc1.br corpus/constructs/poc2.br corpus/constructs/poc3.br corpus/constructs/a2_large.br corpus/constructs/a2_large_min.br corpus/constructs/a2_nsym1.br corpus/constructs/a2_nsym1_short.br corpus/constructs/a2_nsym2.br corpus/constructs/a2_noswitch_ctrl.br corpus/constructs/a2_overshoot_ctrl.br $(ls corpus/seeds/*.br)"
post() { # port vec -> "rc<TAB>body"
  local rc body
  body=$(curl -s -m 20 -w '' --data-binary @"$2" "http://127.0.0.1:$1/decompress-stream" 2>/dev/null); rc=$?
  [ $rc -eq 28 ] && body='{"result":"HANG"}'
  printf '%s\t%s' "$rc" "$body"
}
health() { curl -s -m 5 "http://127.0.0.1:$1/health" 2>/dev/null || echo 'DOWN'; }
echo -e "attempt\tlane\tvector\trcurl\tresult\terrno\tcode\tms\tout\thealth" > "$OUT"
i=0
while [ $i -lt "$N" ]; do
  i=$((i+1))
  for v in $VEC; do
    for lane in vuln ctrl; do
      p=$V; [ $lane = ctrl ] && p=$C
      r=$(post "$p" "$v"); rc=${r%%$'\t'*}; body=${r#*$'\t'}
      res=$(echo "$body" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')
      en=$(echo "$body"  | sed -n 's/.*"errno":\(-\?[0-9a-z]*\).*/\1/p')
      co=$(echo "$body"  | sed -n 's/.*"code":"\([^"]*\)".*/\1/p')
      ms=$(echo "$body"  | sed -n 's/.*"ms":\([0-9.]*\).*/\1/p')
      ob=$(echo "$body"  | sed -n 's/.*"out":\([0-9]*\).*/\1/p')
      h=$(health "$p")
      echo -e "$i\t$lane\t$v\t$rc\t${res:-NOJSON}\t${en:--}\t${co:--}\t${ms:--}\t${ob:--}\t$h" >> "$OUT"
    done
  done
done
