# data/prompts/

The prompt text and few-shot exemplars used across the experiment scripts.

- **few_shot_prompt.txt** — The finalized few-shot extraction prompt: same
  instructions and 6-field JSON schema as the zero-shot prompt, with three
  worked examples included.
- **examples_file.json** — The three few-shot exemplar CVEs (with
  descriptions), in the same order the prompt teaches from. Used by
  `scripts/experiments/few_shot.py`'s leakage gate, which refuses to run
  unless these CVE ids match the ids actually baked into
  `few_shot_prompt.txt`.
- **diverse_candidates.json** — Broader pool of candidate exemplar CVEs
  (with full descriptions/metadata) fetched from *outside* the locked
  500-CVE dataset by `scripts/dataset/fetching_3_for_fewshotreal.py`, from
  which the three final exemplars in `examples_file.json` were chosen —
  spread across attack vector and CIA shape, verified disjoint from the
  evaluation set (the leakage fix documented in `few_shot.py`).
