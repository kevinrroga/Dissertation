# Session Summary — Dataset, Zero-Shot & Few-Shot Experiments
**Project:** LLM-Assisted Triage of Vulnerability Reports (CS957)
**Roadmap position:** Completed through Day 15 prerequisites (Phase 3 done, Phase 4 not started)

---

## 1. Dataset

- **Canonical, frozen dataset:** `dataset_v1_locked_24jun_with_cwe_names.json` — 500 CVEs, identical set/order to the original `dataset_v1_locked_24jun.json`, with a `cwe_names` field added via a **local join only** (no NVD re-fetch, no drift).
- `cwe_names` resolved for 557/559 CWE assignments (99.6%). Two unresolved (`CWE-840`, `CWE-189` — category-level CWEs): **still need manual lookup and patching** before this is used as scoring ground truth. This is outstanding.
- Do not confuse this with `dataset_with_cwe_names.json` (an earlier, discarded re-fetch that had 25 CVEs of drift vs. the locked set) — that file should not be used.

## 2. Zero-shot experiment

- Script: `zero_shot_final.py`. Prompt: 6-field JSON schema (`vulnerability_type`, `attack_vector`, `affected_component`, `confidentiality_impact`, `integrity_impact`, `availability_impact`).
- Full run completed: 3 models (`gpt-5.5`, `claude-sonnet-4.6`, `deepseek-v4-pro`) × 500 CVEs.
- **Bug found and handled:** an Anthropic credit-exhaustion error mid-run caused 40 stale duplicate rows in `claude-sonnet-4.6`'s output (540 rows instead of 500) because the resume logic only checks `valid is True`, never removes old failed rows. Cleaned via `clean_zero_shot_results.py`.
- **Final clean file: `output_of_zero-shot.json`** — 500/500/500 valid, verified no duplicates, no orphaned CVE ids.
- ⚠️ **Not yet fixed:** the root-cause bug in `zero_shot_final.py`'s `completed_cve_ids()`/resume logic is still unpatched at the source. Low priority unless the script is rerun.

## 3. Few-shot experiment

- **Example selection (documented, not arbitrary):** 3 worked examples chosen for diversity across attack vector, vulnerability type, and CIA impact pattern — deliberately sourced **from outside** the locked 500-CVE set (Route A), verified to have zero overlap with the eval set. No leakage.
- Script: `few_shot.py` — includes explicit leakage-consistency gates (`assert_examples_consistent`, `assert_no_leakage`) that block the run if the prompt's examples and the declared example IDs ever diverge.
- Full run completed: 1,500 calls, 500/500/500 valid, zero failures, zero duplicates — confirmed by direct inspection.
- **Format fix:** original run wrote JSONL (`extracted`/`failure_reason` fields). Converted to JSON matching the zero-shot schema (`valid`/`parsed`/`notes`) via `convert_fewshot_jsonl_to_json.py` — no API calls involved, pure reformatting, verified 1,500 lines in → 1,500 rows out, all matched to a description, no orphans.
- **`few_shot.py` was also upgraded** (not just the old run's output): checkpointing now keys on `cve_id` per model (dict, not list), so retries *overwrite* instead of duplicating — the same bug class that hit zero-shot is now structurally impossible here. Also captures `latency_s` per call going forward.
- **Known gap:** `latency_s` is `null` for all 500×3 few-shot rows in this batch — the original script measured call time but never wrote it into the saved row. Not recoverable without re-calling the APIs. **Decision: leave as a disclosed limitation, do not fabricate or estimate it.** State this plainly in Methodology/Discussion; optionally take a small separate 15–20 CVE timing sample later if desired, clearly labeled as not part of the scored 500.
- **Final file: `fewshot_results_final.json`** — verified byte-identical to the converted output, confirmed valid to use.

## 4. Current state of files (keep these; discard superseded versions)

| Keep | Discard / superseded |
|---|---|
| `dataset_v1_locked_24jun_with_cwe_names.json` | `dataset_with_cwe_names.json` (drifted re-fetch) |
| `output_of_zero-shot.json` (cleaned, 500/500/500) | any pre-clean version with 540 claude rows |
| `fewshot_results_final.json` | `results_fewshot-new_file.jsonl`, intermediate `results_fewshot_v1.json` |
| `zero_shot_final.py`, `few_shot.py` (current, patched) | — |

## 5. Outstanding items before Day 15 consolidation

1. Manually resolve the 2 unnamed CWEs (`CWE-840`, `CWE-189`) in the locked dataset.
2. **Day 15 consolidation script not yet built** — needs to: join `output_of_zero-shot.json` + `fewshot_results_final.json` + locked dataset ground truth into one file, one row per (CVE, model, condition), ready for Day 18 scoring. This is the next concrete task.
3. Decision Log entries still to write up (from this session): CWE-name join method, few-shot example selection rationale + leakage exclusion, the claude credit-exhaustion incident, the missing few-shot latency data.

## 6. Immediate next step for the new chat

Ask for the **Day 15 consolidation script** — merge zero-shot + few-shot results with ground truth into one scoring-ready file.
