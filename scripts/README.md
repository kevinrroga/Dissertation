# scripts/

All working pipeline code, split by what stage of the project it belongs to:

- [`fetching/`](fetching/README.md): Day 1–2: pulling raw CVE data out of the NVD API 2.0, one field/endpoint at a time, then blended into one script.
- [`dataset/`](dataset/README.md): Day 3: scaling the fetch loop into the final, locked 500-CVE dataset, plus a fix for a CPE-parsing bug and a spot-check verifier.
- [`experiments/`](experiments/README.md): Day 6–14: the zero-shot vs few-shot prompt experiment runners, from 5-CVE smoke tests up to the full 500-CVE run.
- [`validation/`](validation/README.md): Day 8: the JSON schema validation/retry layer that guards every experiment run against malformed LLM output, plus its own test suite.

Read each subfolder's README for per-file detail; several files share the
same "build_dataset.py" or "test_*.py" docstring header because they're
successive iterations of the same script, not independent tools; the
README for each folder notes which version is the final/superseded one.
