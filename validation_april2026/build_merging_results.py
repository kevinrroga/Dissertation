"""
Build merging_results.json -shaped file for the April-2026 validation set,
so the dissertation's own scoring scripts (score_attack_vector.py,
cia_scorer.py, score_pillar.py, score_affected_component.py) can be run
against it unmodified (just pointed at this file instead of the default
../ultimate_dataset/merging_results.json).

affected_component ground truth is derived from affected_cpes_raw using the
EXACT same vendor/product extraction as building_the_real_dataset.py's
get_affected_components(): split CPE criteria on ':', pair =
f"{parts[3].replace('_',' ')} {parts[4].replace('_',' ')}".
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATASET_PATH = HERE / "validation_dataset.json"
OUTPUT_PATH = HERE / "output_validation_zero_shot.json"
MERGED_PATH = HERE / "merging_results_validation.json"

with open(DATASET_PATH, encoding="utf-8") as f:
    dataset = json.load(f)
gt_by_id = {row["cve_id"]: row for row in dataset}


def cpes_to_components(cpe_list):
    components = []
    for criteria in cpe_list:
        parts = criteria.split(":")
        if len(parts) >= 5:
            pair = f"{parts[3].replace('_', ' ')} {parts[4].replace('_', ' ')}"
            if pair not in components:
                components.append(pair)
    return components


with open(OUTPUT_PATH, encoding="utf-8") as f:
    outputs = json.load(f)

merged = []
for model, rows in outputs.items():
    if not isinstance(rows, list):
        continue  # skip trailing timing-summary scalars (total_time, gpt_time, ...)
    for row in rows:
        cve_id = row["cve_id"]
        gt = gt_by_id[cve_id]
        merged.append({
            "cve_id": cve_id,
            "model": model,
            "prompt_condition": row.get("prompt_condition", "zero_shot"),
            "ground_truth": {
                "attack_vector": gt["attack_vector"],
                "confidentiality_impact": gt["confidentiality_impact"],
                "integrity_impact": gt["integrity_impact"],
                "availability_impact": gt["availability_impact"],
                "cwe_ids": gt["cwe_ids"],
                "affected_component": cpes_to_components(gt["affected_cpes_raw"]),
            },
            "extracted": row.get("parsed") if row.get("valid") else None,
        })

with open(MERGED_PATH, "w", encoding="utf-8") as f:
    json.dump(merged, f, indent=2)

print(f"Wrote {len(merged)} merged records to {MERGED_PATH}")
print(f"Models: {sorted(outputs.keys())}")
print(f"CVEs per model: {len(dataset)}")
