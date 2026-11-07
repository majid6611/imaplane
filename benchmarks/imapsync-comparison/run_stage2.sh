#!/bin/bash
# Stage 2 (replaces the tail of run_all.sh, which was stopped after the SIGKILL stage): the 1,000- and
# 5,000-message scaling runs, then the corrected imapsync-tuned rerun. The 20,000-message test is
# deliberately deferred until after profiling and optimization.
cd "$(dirname "$0")"
L=results/driver.log
say() { echo "$(date +%H:%M:%S) $*" | tee -a $L; }
for n in 1000 5000; do
  say "golden scale-$n";  python3 bench.py golden scale-$n >> $L 2>&1
  say "stage scale-$n";   python3 bench.py run --profile scale-$n --reps 2 --seed 3 --no-newmail --configs imapsync,imapsync-tuned,imaplane,imaplane-stream --out scale-$n >> $L 2>&1
done
say "stage tuned redo (cache on the persistent volume)"
python3 bench.py run --profile mixed --reps 3 --seed 11 --configs imapsync-tuned --out main-mixed-tuned-fixed >> $L 2>&1
say "STAGE2 DONE (scale-20000 deferred)"
