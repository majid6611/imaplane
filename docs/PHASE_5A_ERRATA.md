# Phase 5A report: errata

The raw output of the randomized SIGKILL stress run is preserved unedited in
`docs/benchmarks/phase5a-stress-raw.txt`; `docs/benchmarks/phase5a-stress-summary.json` restates it and
is checked for arithmetic consistency.

The Phase 5A report (chat message, not a repository file) contained two wrong figures for that run.

| Statement in the report | Correct, from the raw output |
|---|---|
| "135 SIGKILLs (67 hook, 49 timed, plus unkilled runs)" | **116** SIGKILLs: 67 by fault hook + 49 by timer. 135 was never a measured number and the parenthesis did not add up. |
| "268 of 270 messages confirmed" | **266 of 270** confirmed (90 + 87 + 89); 4 left in `uncertain` by design (0 + 3 + 1). |

Totals that were right: 224 runs, 191 invariant checks, 0 violations, seed 5001, 15 trials per mode.
Of the 224 runs, 116 were killed, 32 were unkilled `migrate` runs and 76 were the operator procedure
(`recover`, reconcile pass, `resolve`) applied between kills.

Both errors were in the prose summary only. The test, its invariants and its result (0 violations) are
unaffected. The earlier correction about the number of Phase 5A commits (six, not seven) stands.
