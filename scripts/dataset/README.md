# scripts/dataset/

Day 3 deliverable: scaling the Day 1 fetch-and-filter loop from a 5-record
smoke test up to the real, locked 500-CVE dataset
(`data/datasets/dataset_v1_locked_24jun.json`). The four `dataset_*`/
`building_*` scripts are **successive iterations of the same script**, kept
side by side to show the reasoning trail rather than overwriting history —
read them in this order:

1. **building_the_real_dataset.py** — First 500-scale attempt. Adds rate
   limiting and automatic date-window extension on top of the Day 1 logic.
   Single `cwe_id` per record. Output: `build_dataset_output.json`.
2. **dataset_with_rejected_filter_applied.py** — Adds two things: (a)
   skips CVEs with `vulnStatus == "Rejected"`, which can otherwise retain
   stale CVSS/CWE/CPE data that passes the completeness check despite no
   longer describing a real vulnerability, and (b) a `failure_reasons`
   counter + richer end-of-run summary explaining *why* incomplete records
   were dropped. Output: `dataset_minus_rejected.json`.
3. **dataset_walking_backwards.py** — Replaces the growing-window sampling
   with a fixed-anchor, chunk-walking-backward approach (see "SAMPLING
   REDESIGN" in its docstring): the old version filled its whole quota from
   one 48-hour mass-disclosure batch (Linux kernel CVEs) because NVD
   returns oldest-first. This version walks backward from a fixed cutoff
   date in day-sized chunks with a per-day cap, so no single batch can
   dominate. Still single `cwe_id`.
4. **dataset_multiple_cwes.py** — Final version. Same chunk-walking
   redesign as #3, plus `get_vulnerability_types()` returns a **list** of
   CWE IDs (NVD-Primary → NVD-Secondary → CNA-Primary → CNA-Secondary
   precedence) instead of collapsing to one, since some CVEs genuinely
   have more than one weakness type. This is the script that actually
   produced the locked dataset.

Supporting scripts:

- **fix_affected_component.py** — Standalone, offline fix for a CPE
  escaped-colon parsing bug found during the Day 3 spot-check (e.g. Perl's
  `Archive::Tar` breaking naive `:`-splitting). Re-derives
  `affected_component` from the already-fetched `affected_cpes_raw` for
  every record — makes no new NVD API calls — and prints old vs. new value
  for anything it changes.
- **fetching_3_for_fewshotreal.py** — Self-contained helper (Day 7) that
  fetches candidate CVEs from *outside* the locked 500, spread across
  attack vector and CIA shape, so few-shot exemplars can be chosen without
  leaking into the evaluation set. Output feeds
  `data/prompts/diverse_candidates.json`.

See [`../validation/verify_sample.py`](../validation/README.md) for the
spot-check that re-fetches a sample of the locked dataset live from NVD and
diffs it against what's stored.
