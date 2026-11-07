#!/bin/bash
# Runs after run_all.sh: repeat the imapsync-tuned chains with the UID cache on the persistent volume
# (the first attempt, in main-mixed, had a harness defect: the cache was lost between runs).
cd "$(dirname "$0")"
while pgrep -f run_all.sh > /dev/null; do sleep 30; done
echo "$(date +%H:%M:%S) stage tuned redo" >> results/driver.log
python3 bench.py run --profile mixed --reps 3 --seed 11 --configs imapsync-tuned --out main-mixed-tuned-fixed >> results/driver.log 2>&1
echo "$(date +%H:%M:%S) TUNED REDO DONE" >> results/driver.log
