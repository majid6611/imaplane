#!/bin/bash
# Staged, unattended benchmark. Each stage appends to results/<name>/runs.jsonl; stages are independent.
cd "$(dirname "$0")"
L=results/driver.log; mkdir -p results
say() { echo "$(date +%H:%M:%S) $*" | tee -a $L; }
say "golden mixed";        python3 bench.py golden mixed          >> $L 2>&1
say "stage main (mixed, 3 reps, 4 configs, interleaved)"
python3 bench.py run --profile mixed --reps 3 --seed 1 --out main-mixed >> $L 2>&1
python3 - <<'PY' >> $L 2>&1
import json, statistics, collections
w = collections.defaultdict(list)
for l in open('results/main-mixed/runs.jsonl'):
    r = json.loads(l)
    if r['step'] == 'fresh':
        w[r['cfg']].append(r['wall_s'])
json.dump({k: statistics.median(v) for k, v in w.items()}, open('results/fresh-medians-mixed.json', 'w'))
print('fresh medians', {k: round(statistics.median(v), 1) for k, v in w.items()})
PY
say "stage kill (mixed)"
python3 bench.py kill --profile mixed --kills 4 --seed 7 --fresh-medians results/fresh-medians-mixed.json --out kill-mixed >> $L 2>&1
for n in 1000 5000; do
  say "golden scale-$n";  python3 bench.py golden scale-$n >> $L 2>&1
  say "stage scale-$n";   python3 bench.py run --profile scale-$n --reps 2 --seed 3 --no-newmail --configs imapsync,imapsync-tuned,imaplane,imaplane-stream --out scale-$n >> $L 2>&1
done
say "golden scale-20000"; python3 bench.py golden scale-20000 >> $L 2>&1
say "stage scale-20000";  python3 bench.py run --profile scale-20000 --reps 1 --seed 5 --no-newmail --configs imapsync,imaplane --out scale-20000 >> $L 2>&1
say "ALL STAGES DONE"
