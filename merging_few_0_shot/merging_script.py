"""
consolidate_results.py
=======================
Day 15: merges zero-shot results + few-shot results + ground truth from the
locked dataset into ONE flat file, ready for Day 18 scoring.

Input files (must all score/cover the same 500-CVE locked set):
  - output_of_zero-shot_tidy.json   (500 CVEs x 3 models, prompt_condition=zero_shot)
  - results_fewshot_v1_tidy.json    (500 CVEs x 3 models, prompt_condition=few_shot)
  - dataset_v1_locked_24jun_with_cwe_names.json  (ground truth)

Output: one JSON file, a flat list of 3,000 rows (500 CVEs x 3 models x 2
conditions). Each row has the LLM's 6 extracted fields sitting next to the
matching ground truth for that CVE, ready for a scoring script to iterate
over directly (or load into pandas) without needing to touch three separate
files or three separate schemas.

Deliberately excluded from the output, and why:
  - raw_response / description: already live in the two source result files
    as the audit trail. Including them here would duplicate ~6x per CVE
    (3 models x 2 conditions) for no scoring benefit -- bloat, not data.
  - No normalization of ground truth vs extracted values (e.g. "HIGH" vs
    "High", "ADJACENT_NETWORK" vs "Adjacent Network"). That casing/format
    mismatch is real and matters, but deciding HOW to match them (exact
    string match after normalization? substring? mapping table?) is a
    Day 18 scoring decision, not a Day 15 consolidation decision. Baking an
    assumption in here would hide that decision instead of making it explicit.

Usage:
    python consolidate_results.py
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ZERO_SHOT_PATH = ROOT / "output_of_zero-shot_tidy.json"
FEW_SHOT_PATH = ROOT / "results_fewshot_v1_tidy.json"
LOCKED_DATASET_PATH = ROOT / "dataset_v1_locked_24jun_with_cwe_names.json"
OUTPUT_PATH = ROOT / "consolidated_results.json"

MODELS = ["gpt-5.5", "claude-sonnet-4.6", "deepseek-v4-pro"]

EXTRACTED_FIELDS = [
    "vulnerability_type",
    "attack_vector",
    "affected_component",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]


def load_ground_truth(path: Path) -> dict:
    """Returns {cve_id: ground_truth_row}."""
    with path.open(encoding="utf-8") as f:
        records = json.load(f)
    return {r["cve_id"]: r for r in records}


def build_row(result_row: dict, ground_truth: dict, prompt_condition: str) -> dict:
    """One consolidated row: identifiers at the top level, the model's 6
    fields nested under "extracted", and the matching NVD fields nested
    under "ground_truth" -- same information as before, just grouped so the
    two sides don't need a naming prefix to tell them apart."""
    parsed = result_row.get("parsed") or {}
    gt = ground_truth.get(result_row["cve_id"], {})

    return {
        "cve_id": result_row["cve_id"],
        "model": result_row["model"],
        "prompt_condition": prompt_condition,
        "valid": result_row.get("valid", False),
        "extracted": {
            field: parsed.get(field) for field in EXTRACTED_FIELDS
        },
        "ground_truth": {
            "vulnerability_type": gt.get("cwe_names"),
            "attack_vector": gt.get("attack_vector"),
            "affected_component": gt.get("affected_components"),
            "confidentiality_impact": gt.get("confidentiality_impact"),
            "integrity_impact": gt.get("integrity_impact"),
            "availability_impact": gt.get("availability_impact"),
            "cwe_ids": gt.get("cwe_ids"),
        },
    }


def consolidate(zero_shot: dict, few_shot: dict, ground_truth: dict) -> list:
    rows = []
    for model in MODELS:
        for result_row in zero_shot[model]:
            rows.append(build_row(result_row, ground_truth, "zero_shot"))
        for result_row in few_shot[model]:
            rows.append(build_row(result_row, ground_truth, "few_shot"))
    return rows


def main():
    for path in (ZERO_SHOT_PATH, FEW_SHOT_PATH, LOCKED_DATASET_PATH):
        if not path.exists():
            raise SystemExit(f"Missing required input file: {path}")

    with ZERO_SHOT_PATH.open(encoding="utf-8") as f:
        zero_shot = json.load(f)
    with FEW_SHOT_PATH.open(encoding="utf-8") as f:
        few_shot = json.load(f)
    ground_truth = load_ground_truth(LOCKED_DATASET_PATH)

    print(f"Ground truth: {len(ground_truth)} CVEs")
    for model in MODELS:
        print(f"  zero-shot/{model}: {len(zero_shot[model])} rows")
        print(f"  few-shot/{model}: {len(few_shot[model])} rows")

    rows = consolidate(zero_shot, few_shot, ground_truth)

    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)

    print(f"\nConsolidated {len(rows)} rows -> {OUTPUT_PATH}")

    # ---- Verification, not just a hopeful print statement ----
    expected = len(MODELS) * 2 * len(ground_truth)
    assert len(rows) == expected, f"expected {expected} rows, got {len(rows)}"

    missing_gt = [r for r in rows if r["ground_truth"]["attack_vector"] is None]
    if missing_gt:
        print(f"WARNING: {len(missing_gt)} rows have no matching ground truth "
              f"(cve_id not found in locked dataset) -- check for id mismatches.")
    else:
        print("Every row matched to ground truth: OK")

    by_condition = {}
    for r in rows:
        by_condition.setdefault(r["prompt_condition"], 0)
        by_condition[r["prompt_condition"]] += 1
    print(f"Row counts by condition: {by_condition}")

    valid_counts = {}
    for r in rows:
        key = (r["model"], r["prompt_condition"])
        valid_counts.setdefault(key, [0, 0])
        valid_counts[key][0] += 1
        if r["valid"]:
            valid_counts[key][1] += 1
    print("\nValid rows per (model, condition):")
    for (model, cond), (total, valid) in sorted(valid_counts.items()):
        print(f"  {model} / {cond}: {valid}/{total} valid")


if __name__ == "__main__":
    main()