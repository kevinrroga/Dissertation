# Day 15: Clean and Consolidate Raw Results

**Roadmap phase:** Phase 4, Day 15 (per original roadmap task: "One clean, structured file containing every LLM output, matched to its CVE and condition")

## What was done today

### 1. Built the consolidation script
Created `consolidate_results.py`, which merges three separate sources into one file:
- `output_of_zero-shot_tidy.json` (zero-shot results, 3 models × 500 CVEs)
- `results_fewshot_v1_tidy.json` (few-shot results, 3 models × 500 CVEs)
- `dataset_v1_locked_24jun_with_cwe_names.json` (ground truth)

Joined on `cve_id`, producing one row per (CVE, model, prompt_condition) combination.

### 2. Verified before trusting it
- Confirmed both result files score **exactly** the same 500 CVEs as the locked dataset (no drift, no leakage-example contamination) before building the join.
- Ran the script: **3,000 rows produced** (500 CVEs × 3 models × 2 conditions), matching the expected count exactly.
- Every row matched to ground truth (0 missing).
- 500/500 valid for every (model, condition) pair (no gaps to backfill).

### 3. Restructured row format (mid-session improvement)
Original format used a `gt_` prefix on ground truth fields (e.g. `gt_attack_vector`) sitting flat alongside the extracted fields. Restructured into two nested blocks per row for clarity:

```json
{
  "cve_id": "...",
  "model": "...",
  "prompt_condition": "...",
  "valid": true,
  "extracted": {
    "vulnerability_type": "...",
    "attack_vector": "...",
    "affected_component": "...",
    "confidentiality_impact": "...",
    "integrity_impact": "...",
    "availability_impact": "..."
  },
  "ground_truth": {
    "vulnerability_type": ["..."],
    "attack_vector": "...",
    "affected_component": ["..."],
    "confidentiality_impact": "...",
    "integrity_impact": "...",
    "availability_impact": "...",
    "cwe_ids": ["..."]
  }
}
```

Field names are now **identical** between `extracted` and `ground_truth` (except `cwe_ids`, which has no extracted counterpart). This was a deliberate choice to make the upcoming Day 18 scoring script simpler to write. Reran and reverified after the restructure: same 3,000 rows, same 500/500 valid counts, no data lost.

### 4. Deliberate exclusions from this file (documented, not oversights)
- **`raw_response` / `description` excluded.** Already live in the two source result files as the audit trail; including them here would duplicate 6× per CVE for no scoring benefit.
- **No normalization applied to ground truth vs. extracted values.** E.g. `"HIGH"` (ground truth) vs `"High"` (extracted) are left exactly as each source reported them. Deciding how to match these is a Day 18 scoring decision, not a Day 15 consolidation decision. Baking it in here would hide that decision instead of making it explicit.

## Known mismatches identified today (to resolve on Day 18, not before)

These are **not bugs**: both sides of each mismatch are individually correct, they just use different formats. Confirmed by checking the actual value sets in the consolidated file:

1. **`attack_vector` / CIA impacts: format mismatch only.** Fixed, small vocabularies on both sides (4 categories for attack_vector, 3 + null for CIA). Fix: a simple lookup-table normalization at scoring time (not a fuzzy-matching problem).
   - Extracted: `Network`, `Adjacent Network`, `Local`, `Physical`
   - Ground truth: `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL`

2. **`null` vs `"None"` distinction in extracted CIA values.** These mean different things: `null` = model gave no answer; `"None"` = model explicitly said "no impact." Ground truth has no `null` equivalent. Must be scored as different outcomes, not conflated.

3. **`vulnerability_type`: bigger mismatch, same matching philosophy as `affected_component`.** Ground truth is full CWE definitional names (e.g. `"Missing Authentication for Critical Function"`); extracted values are short category labels (e.g. `"Missing Authentication"`). Decision: apply the same normalize + token-overlap matching approach already locked in for `affected_component` back on Day 2, rather than requiring exact string match. Recommendation: report **both** strict exact-match and token-overlap match rates side by side in Results; the gap between them is itself a reportable finding about LLM output style vs. formal taxonomy (ties into Discussion, alongside Marchiori et al.'s CIA-subjectivity finding).

4. **`ground_truth.vulnerability_type` and `ground_truth.affected_component` are lists**, since a CVE can have multiple CWEs/components; extracted values are single strings. Day 18 matching functions need to check against *any* entry in the list, not assume a 1:1 comparison.

## Explicitly NOT done today (by choice, to avoid rushing ahead)
- Day 18 scoring script itself: not started. Matching rules discussed and agreed in principle (see above) but not implemented.
- No rerunning of zero-shot or few-shot experiments was needed or done. All mismatches found today are scoring-time formatting issues, not data collection problems.

## Next session: Day 18: Build the scoring script
Goal: precision/recall/F1 per entity type, per model, per condition, using `consolidated_results.json` as-is (no changes needed to that file first). Implement:
- Lookup-table exact match for `attack_vector` and CIA impacts (with `null` handled as its own outcome, not merged into `"None"`)
- Normalize + token-overlap match for `vulnerability_type` and `affected_component`, reporting both strict and overlap match rates for `vulnerability_type`
- Output: a results table (rows = entity type, columns = model × condition, values = precision/recall/F1)
