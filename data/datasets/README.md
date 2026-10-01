# data/datasets/

The CVE dataset across its build iterations; see
[`../../scripts/dataset/README.md`](../../scripts/dataset/README.md) for the
full lineage of the scripts that produced each file.

- **build_dataset_output.json**: Output of `building_the_real_dataset.py`,
  the first 500-scale attempt (single `cwe_id`, growing date window).
- **dataset_minus_rejected.json**: Output of
  `dataset_with_rejected_filter_applied.py` / `dataset_walking_backwards.py`
  / `dataset_multiple_cwes.py` (all three write to this same filename as
  the sampling logic was iterated); CVEs with `vulnStatus == "Rejected"`
  excluded.
- **dataset_v1_locked_24jun.json**: **The locked dataset.** Final,
  500-record set produced by `dataset_multiple_cwes.py` (multi-CWE support,
  chunk-walking sampling, per-day cap), locked 24 June 2026. This is the
  dataset every experiment script in `scripts/experiments/` and
  `chatgpt_interference/` reads from.
