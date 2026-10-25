#!/usr/bin/env bash
# brot-glm2 step 3: express surface sweep (body-parser raw/json + express ejson),
# POST Content-Encoding: br, OUR app, OUR corpus.
set -u
V=${1:-8126}; C=${2:-8127}; OUT=${3:-/dev/stdout}; N=${4:-50}
VEC="corpus/constructs/poc0.br corpus/constructs/poc1.br corpus/constructs/poc2.br corpus/constructs/poc3.br corpus/constructs/a2_large.br corpus/constructs/a2_large_min.br corpus/constructs/a2_nsym1.br corpus/constructs/a2_nsym1_short.br corpus/constructs/a2_nsym2.br corpus/constructs/a2_noswitch_ctrl.br corpus/constructs/a2_overshoot_ctrl.br $(ls corpus/seeds/*.br)"
post() { local rc body
  body=$(curl -s -m 20 -H 'Content-Encoding: br' --data-binary @"$2" "http://127.0.0.1:$1/$3" 2>/dev/null); rc=$?
  [ $rc -eq 28 ] && body='{"result":"HANG"}'
  printf '%s\t%s' "$rc" "$body"; }
health() { curl -s -m 5 "http://127.0.0.1:$1/health" 2>/dev/null || echo 'DOWN'; }
echo -e "attempt\tlane\troute\tvector\trcurl\tresult\terrno\thealth" > "$OUT"
i=0
while [ $i -lt "$N" ]; do
  i=$((i+1))
  for v in $VEC; do
    for route in raw json ejson; do
      for lane in vuln ctrl; do
        p=$V; [ $lane = ctrl ] && p=$C
        r=$(post "$p" "$v" "$route"); rc=${r%%$'\t'*}; body=${r#*$'\t'}
        res=$(echo "$body" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')
        en=$(echo "$body"  | sed -n 's/.*"errno":\(-\?[0-9]*\).*/\1/p')
        [ -z "$res" ] && { echo "$body" | grep -q '"ok":true' && res=ok || res=NOJSON; }
        h=$(health "$p")
        echo -e "$i\t$lane\t$route\t$v\t$rc\t${res:-NOJSON}\t${en:--}\t$h" >> "$OUT"
      done
    done
  done
done
