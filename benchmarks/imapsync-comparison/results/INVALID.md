# Invalid or discarded results (kept for the record; never used in tables)

Harness defects are listed here separately from product defects. None of the entries below is a defect of
IMAPLANE or imapsync.

| Result | Why it is invalid | Kind | Evidence kept |
|---|---|---|---|
| `main-mixed`, config `imapsync-tuned`, steps `rerun`, `newmail1`, `newmail2` | `--useuid` keeps its UID cache in imapsync's temp dir. The tool container is throwaway, so the cache was lost between runs and imapsync re-copied the whole mailbox on every rerun (3,280 extra messages per run, 6,560 and 10,040 duplicates after the new-mail steps). The `fresh` step of that config is valid. Redone as `main-mixed-tuned-fixed` with the cache on the persistent volume. | harness defect (configuration) | `main-mixed/runs.jsonl`, `main-mixed/invalid.json` |
| first `scale-1000` stage (2026-11-06 18:29) | A second launch of the stage script rebuilt the `scale-1000` golden dataset underneath the running stage; the run crashed on a missing `info.json`. No measurement was recorded. | harness defect (no isolation / no execution lock) | `driver.log` (traceback), directory `INVALID-scale-1000-aborted-by-harness-defect` |
| second `scale-1000` stage (2026-11-06 18:30-18:46) | Stopped by the operator before completing so the isolation defect could be fixed first. Partial, discarded. | operator stop | `driver.log`, same directory |
