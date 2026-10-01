# reports/

Human-readable summaries derived from the raw results in
[`../data/results/`](../data/results/README.md).

- **day6_metrics.csv**: Per-model validity/latency/token/cost metrics for
  the full 500-CVE zero-shot run (`scripts/experiments/day11_zero_shot_real.py`).
- **day9_pilot_failures.csv**: Per-model, per-condition mechanical failure
  rate and PROCEED/FIX-AND-REPILOT verdict from the Day 9 pilot
  (`scripts/experiments/day9.py`).
- **day9_pilot_inspection.txt**: Paired extraction-vs-description text for
  manual eyeball checking of the Day 9 pilot; a mechanical pass does not
  prove the extractions are semantically correct, this is the human check.
- **fewshot_run_log.txt**: Console log captured from a `few_shot.py` run.
- **verification_report.json**: Output of the Day 3 spot-check
  (`scripts/validation/verify_sample.py`): live NVD re-fetch vs. stored
  dataset diff for a random sample, with raw evidence per record.
- **zero-shot-prompt-v2-test-10cves-metrics.csv**: Per-model metrics for
  the 10-CVE "prompt v2" pilot
  (`chatgpt_interference/test_zero_shot_prompt_v2_10cves.py`).
