# scripts/experiments/

The zero-shot vs few-shot prompting experiments (RQ2), scaling from 5-CVE
smoke tests up to the full 500-CVE run across all three models (GPT-5.5,
Claude Sonnet 4.6, DeepSeek V4-Pro). All scripts call the models with
reasoning/thinking off and temperature 0 for an identical decoding config
across providers.

- **test_zero_shot_prompt.py** — Day 6 deliverable. Sends the finalized
  zero-shot extraction prompt to all three models for 5 test CVEs and
  validates the 6-field JSON schema. This is the prompt template later
  reused verbatim by every other zero-shot script in the project.
- **test_few_shot_prompt.py** — Day 7 deliverable. Identical to
  `test_zero_shot_prompt.py` except the prompt template adds three worked
  examples — the only experimental delta between conditions, which is what
  keeps the zero-shot vs few-shot comparison clean. Documents the 3
  exemplar CVEs chosen (diversity across vulnerability type / attack
  vector) and flags that, for this pilot, they were drawn from *inside*
  the locked 500-CVE set (a leakage issue resolved later — see
  `few_shot.py`).
- **day9.py** — Day 9 pilot harness. Reuses the model-call/retry/
  validation machinery from the two scripts above verbatim; adds a
  deterministic 20-CVE sampler (excluding the few-shot exemplars), runs
  both conditions in one pass, and reports a per-model/per-condition
  mechanical failure rate with a PROCEED / FIX-AND-REPILOT verdict.
  Outputs: `data/results/day9_pilot_raw.json`,
  `data/results/day9_pilot_sample_cves.json`,
  `reports/day9_pilot_failures.csv`, `reports/day9_pilot_inspection.txt`
  (a human-eyeball file — mechanical pass rate doesn't prove the
  extractions are semantically *correct*).
- **day11_zero_shot_real.py** — The full zero-shot run: all 500 CVEs in
  the locked dataset, all three models (`NUM_TEST_CVES = 500`, overridable
  from the command line for a smaller pilot). Output:
  `data/results/zero-shot-real-day11.json`, metrics to
  `reports/day6_metrics.csv`.
- **few_shot.py** — Day 13–14 full few-shot run (3 models × 500 CVEs).
  Fixes three issues found in the Day 7 pilot: (1) the model-call functions
  were unimplemented stubs — now inlined with real bodies; (2) the model
  list mistakenly said Opus 4.7 — corrected to Sonnet 4.6, since Opus
  rejects a user-set temperature; (3) the leakage gate checked one file
  while the prompt actually taught from a different hardcoded example
  set — it now refuses to run unless they match. Also documents the
  resolved data-leakage decision: exemplars were replaced with 3 CVEs
  verified disjoint from the locked 500 (ROUTE A, confirmed 5 Jul 2026).
  Output: `data/results/results_fewshot.jsonl`.
  *(Moved here from the repo root — it belongs with the rest of the
  experiment runners and expects the same `data/`/`reports/` relative
  layout as its siblings.)*

See [`../../chatgpt_interference/`](../../chatgpt_interference/README.md)
for a parallel set of zero-shot pilot/final scripts developed with ChatGPT,
and [`../validation/`](../validation/README.md) for the schema
validation/retry layer all of these scripts rely on.
