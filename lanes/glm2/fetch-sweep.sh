#!/usr/bin/env bash
# brot-glm2 step 4: fetch-victim sweep — victim fetches OUR vectors from OUR
# evil-origin (chunked 1KB corked delivery); OUR code only.
set -u
V=${1:-8128}; C=${2:-8131}; OUT=${3:-/dev/stdout}; N=${4:-50}
names_constructs="poc0.br poc1.br poc2.br poc3.br a2_large.br a2_large_min.br a2_nsym1.br a2_nsym1_short.br a2_nsym2.br a2_noswitch_ctrl.br a2_overshoot_ctrl.br"
names_seeds=$(cd corpus/seeds && ls *.br)
health() { curl -s -m 5 "http://127.0.0.1:$1/health" 2>/dev/null || echo 'DOWN'; }
echo -e "attempt\tlane\tvector\trcurl\tresult\terrno\tcode\tms\thealth" > "$OUT"
i=0
while [ $i -lt "$N" ]; do
  i=$((i+1))
  for n in $names_constructs; do
    for lane in vuln ctrl; do
      p=$V; [ $lane = ctrl ] && p=$C
      body=$(curl -s -m 20 -H 'Content-Type: application/json' -d "{\"name\":\"$n\",\"dir\":\"constructs\"}" "http://127.0.0.1:$p/check-url" 2>/dev/null); rc=$?
      [ $rc -eq 28 ] && body='{"result":"HANG"}'
      res=$(echo "$body" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p'); en=$(echo "$body" | sed -n 's/.*"errno":\(-\?[0-9]*\).*/\1/p'); co=$(echo "$body" | sed -n 's/.*"code":"\([^"]*\)".*/\1/p'); ms=$(echo "$body" | sed -n 's/.*"ms":\([0-9.]*\).*/\1/p')
      echo -e "$i\t$lane\tconstructs/$n\t$rc\t${res:-NOJSON}\t${en:--}\t${co:--}\t${ms:--}\t$(health $p)" >> "$OUT"
    done
  done
  for n in $names_seeds; do
    for lane in vuln ctrl; do
      p=$V; [ $lane = ctrl ] && p=$C
      body=$(curl -s -m 20 -H 'Content-Type: application/json' -d "{\"name\":\"$n\",\"dir\":\"seeds\"}" "http://127.0.0.1:$p/check-url" 2>/dev/null); rc=$?
      [ $rc -eq 28 ] && body='{"result":"HANG"}'
      res=$(echo "$body" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p'); en=$(echo "$body" | sed -n 's/.*"errno":\(-\?[0-9]*\).*/\1/p'); co=$(echo "$body" | sed -n 's/.*"code":"\([^"]*\)".*/\1/p'); ms=$(echo "$body" | sed -n 's/.*"ms":\([0-9.]*\).*/\1/p')
      echo -e "$i\t$lane\tseeds/$n\t$rc\t${res:-NOJSON}\t${en:--}\t${co:--}\t${ms:--}\t$(health $p)" >> "$OUT"
    done
  done
done
