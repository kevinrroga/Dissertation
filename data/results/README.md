# data/results/

Raw output from every experiment run. Filenames map to the script that
produced them; see [`../../scripts/experiments/README.md`](../../scripts/experiments/README.md)
and [`../../chatgpt_interference/README.md`](../../chatgpt_interference/README.md).

- **day6_results.json**: 5-CVE zero-shot pilot, from
  `scripts/experiments/test_zero_shot_prompt.py`.
- **day7_results_fewshot.json**: 5-CVE few-shot pilot, from
  `scripts/experiments/test_few_shot_prompt.py`.
- **day9_pilot_raw.json** / **day9_pilot_sample_cves.json**: 20-CVE ×
  {zero-shot, few-shot} × 3-model pilot and its sampled CVE set, from
  `scripts/experiments/day9.py`.
- **zero-shot-real-day11.json**: Full 500-CVE zero-shot run, from
  `scripts/experiments/day11_zero_shot_real.py`.
- **results_fewshot.jsonl**: Full 500-CVE few-shot run (current), from
  `scripts/experiments/few_shot.py`.
- **results_fewshot_OLD_106rows_20260705_161312.jsonl** /
  **results_fewshot_OLD_pre-5jul-examples.jsonl**: Superseded partial/earlier
  few-shot runs, kept for history rather than deleted (e.g. before the 5 Jul
  2026 exemplar-leakage fix documented in `few_shot.py`). Do not use these
  for the final analysis.
- **0shotchatgpt.json** / **0shotchatgpt_v2.json** / **0shotchatgpt_v3.json**:
  Zero-shot runs from the `chatgpt_interference/` scripts; `v3` is current
  (see that folder's README for why the docstrings undersell this).
- **zero-shot-prompt-v2-test-10cves.json**: 10-CVE "prompt v2" pilot, from
  `chatgpt_interference/test_zero_shot_prompt_v2_10cves.py`.
