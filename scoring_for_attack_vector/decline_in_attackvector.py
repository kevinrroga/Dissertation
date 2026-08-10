"""
Declines overlap analysis - attack vector.

Run from cve-ner-dissertation/scoring_for_attack_vector/
    python declines_attack_vector.py

Reads : ../ultimate_dataset/merging_results.json
Writes: declines_attack_vector_report.txt
        declines_attack_vector_results.json

Requires: nothing beyond the standard library.

Question
--------
GPT-5.5 declines (returns no value) far more often than the other models. Are
those declines on the SAME CVEs the other models also find hard (a property of
the data), or are they GPT-specific (a property of the model)? And when GPT
declines, do the other models succeed on that CVE anyway?

Method
------
Per model, pool both prompting conditions: a CVE is "declined" if the model
returned null for it in at least one condition. Then:
  - count how many models declined each CVE (3, 2, or 1);
  - list the CVEs declined by all models (the shared hard core);
  - count each model's unique declines (declined by it alone);
  - for the highest-declining model, cross-reference: on the CVEs it declined,
    how did the other models fare? ("wrong" = incorrect in BOTH conditions, a
    deliberately strict bar - state this when reporting.)
"""

import json
import os
from collections import defaultdict

ENTITY = "attack_vector"
CLASSES = {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}
INPUT = os.path.join("..", "ultimate_dataset", "merging_results.json")


def normalise(value):
    if not isinstance(value, str):
        return None
    label = "_".join(value.strip().strip(".,;:").lower().split()).replace("-", "_").upper()
    return label if label in CLASSES else None


def main():
    if not os.path.exists(INPUT):
        raise SystemExit(f"Not found: {INPUT}\nRun from scoring_for_attack_vector/.")

    with open(INPUT, encoding="utf-8") as f:
        rows = json.load(f)

    models = sorted({r["model"] for r in rows})

    declined = defaultdict(set)              # model -> {cve declined in >=1 condition}
    correct = defaultdict(lambda: defaultdict(dict))  # model -> cve -> cond -> 0/1

    for r in rows:
        m, cond, cve = r["model"], r["prompt_condition"], r["cve_id"]
        raw = r["extracted"].get(ENTITY)
        gt = r["ground_truth"].get(ENTITY)
        if raw is None:
            declined[m].add(cve)
        correct[m][cve][cond] = int(normalise(raw) == gt)

    # overlap
    all_declined = set()
    for m in models:
        all_declined |= declined[m]

    by_count = defaultdict(list)
    for cve in all_declined:
        k = sum(1 for m in models if cve in declined[m])
        by_count[k].append(cve)

    shared = set(all_declined)
    for m in models:
        shared &= declined[m]

    unique = {}
    for m in models:
        unique[m] = sorted(
            cve for cve in declined[m]
            if sum(1 for mm in models if cve in declined[mm]) == 1
        )

    # cross-reference for the highest-declining model
    top = max(models, key=lambda m: len(declined[m]))
    others = [m for m in models if m != top]

    def wrong_on(model, cve):
        vals = list(correct[model].get(cve, {}).values())
        return all(v == 0 for v in vals) if vals else True  # strict: wrong in both conditions

    both_wrong = sum(1 for cve in declined[top] if all(wrong_on(m, cve) for m in others))
    both_right = sum(1 for cve in declined[top] if all(not wrong_on(m, cve) for m in others))
    mixed = len(declined[top]) - both_wrong - both_right

    # ---- report ----
    lines = []
    def out(s=""):
        print(s)
        lines.append(s)

    out(f"Declines overlap analysis - {ENTITY}")
    out("A CVE is 'declined' by a model if it returned null in >=1 condition (pooled).")
    out("")
    out("Declined-CVE set size per model:")
    for m in models:
        out(f"  {m:24} {len(declined[m])}")
    out("")
    out(f"Overlap across {len(models)} models:")
    for k in sorted(by_count, reverse=True):
        out(f"  declined by {k}: {len(by_count[k])} CVEs")
    out("")
    out(f"Shared hard core (declined by ALL {len(models)}): {len(shared)} CVEs")
    for cve in sorted(shared):
        out(f"    {cve}")
    out("")
    out("Model-specific declines (declined by that model alone):")
    for m in models:
        out(f"  {m:24} {len(unique[m])}")
    out("")
    out(f"Cross-reference: on the {len(declined[top])} CVEs {top} declined,")
    out(f"how did the other models do? ('wrong' = incorrect in BOTH conditions)")
    out(f"  both other models also wrong: {both_wrong}")
    out(f"  both other models correct:    {both_right}")
    out(f"  mixed:                        {mixed}")
    out("")
    out("Reading: a large shared core points to hard descriptions (data); a large")
    out("model-specific count points to a behavioural difference (that model is")
    out("simply more willing to abstain).")

    with open("declines_attack_vector_report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    with open("declines_attack_vector_results.json", "w") as f:
        json.dump({
            "entity": ENTITY,
            "declined_count_per_model": {m: len(declined[m]) for m in models},
            "overlap_by_count": {str(k): sorted(v) for k, v in by_count.items()},
            "shared_all_models": sorted(shared),
            "unique_per_model": unique,
            "cross_reference_top_decliner": {
                "model": top,
                "both_others_wrong": both_wrong,
                "both_others_correct": both_right,
                "mixed": mixed,
                "wrong_definition": "incorrect in both conditions",
            },
        }, f, indent=2)

    print("\nWritten: declines_attack_vector_report.txt")
    print("Written: declines_attack_vector_results.json")


if __name__ == "__main__":
    main()