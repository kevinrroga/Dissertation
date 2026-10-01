# data/

All inputs and outputs produced by the scripts in [`../scripts/`](../scripts/README.md)
and [`../chatgpt_interference/`](../chatgpt_interference/README.md).

- [`nvd_steps/`](nvd_steps/README.md): Day 1–2 intermediate outputs, one
  per field-extraction step, from building the fetch pipeline incrementally.
- [`datasets/`](datasets/README.md): the CVE dataset itself, across its
  build iterations, ending in the locked 500-CVE set used for every
  experiment.
- [`prompts/`](prompts/README.md): the zero-shot/few-shot prompt text and
  the few-shot exemplar CVEs.
- [`model_samples/`](model_samples/README.md): one raw sample response
  per provider, from the Day 5 connectivity tests.
- [`results/`](results/README.md): every experiment run's raw output
  (pilot, full zero-shot, full few-shot, and their supersede history).
