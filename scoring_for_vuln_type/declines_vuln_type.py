"""
Declines overlap analysis — vulnerability type.

Run from cve-ner-dissertation/scoring_for_vulnerability_type/
    python declines_vulnerability_type.py

Reads : vulnerability_type_pillar_scored_details.json
Writes: declines_vulnerability_type_report.txt
        declines_vulnerability_type_results.json

Requires: nothing beyond the standard library.

Direct port of decline_in_attackvector.py, adapted for vulnerability type.
The logic and output structure are identical so results are directly
comparable across entities.

Question
--------
Do any models return null (no predicted label) for vulnerability type, and
if so, is that a property of the data (the CVE descriptions are genuinely
hard) or a property of the model (that model is simply more willing to
abstain)? When a model declines, do the other models succeed on that CVE?

Method (identical to attack_vector and CIA decline scripts)
-----------------------------------------------------------
Per model, pool both prompting conditions: a CVE is "declined" if the model
returned a null predicted_label in at least one condition. Then:
  - count how many models declined each CVE (3, 2, or 1);
  - list CVEs declined by all models (the shared hard core);
  - count each model's unique declines (declined by it alone);
  - for the highest-declining model, cross-reference: on the CVEs it
    declined, how did the other models fare?
    ("wrong" = incorrect in BOTH conditions — deliberately strict bar,
     same definition as attack_vector and CIA decline scripts).

Source file
-----------
Unlike attack_vector (which reads merging_results.json directly and
re-normalises predictions), this script reads the already-scored
vulnerability_type_pillar_scored_details.json. The null check is on
predicted_label (None = model returned no value). Correctness is read
from layer_1_result ("correct"/"incorrect") — the same definition used
in the headline summary table and the McNemar script.

NOTE ON EXPECTED RESULTS:
    Based on the scored data: only DeepSeek-v4-pro produces null predictions
    on this entity (4 CVEs across both conditions). Claude-sonnet-4.6 and
    GPT-5.5 never abstain. All 4 DeepSeek declines are model-specific
    (no other model also declined them), pointing to a behavioural difference
    rather than a shared data-difficulty property. This is the finding to
    report.
"""

import json
import os
from collections import defaultdict

INPUT = "vulnerability_type_pillar_scored_details.json"
REPORT_PATH = "declines_vulnerability_type_report.txt"
RESULTS_PATH = "declines_vulnerability_type_results.json"


def load_data(path):
    """
    Return:
      declined: {model: set of cve_ids declined in >=1 condition}
      correct:  {model: {cve_id: {condition: bool}}}
      models:   sorted list of model names
    """
    with open(path, encoding="utf-8") as f:
        records = json.load(f)

    models = sorted({r["model"] for r in records})
    declined = defaultdict(set)
    correct = defaultdict(lambda: defaultdict(dict))

    for r in records:
        m = r["model"]
        cve = r["cve_id"]
        cond = r["prompt_condition"]

        if r["predicted_label"] is None:
            declined[m].add(cve)

        correct[m][cve][cond] = (r["layer_1_result"] == "correct")

    return declined, correct, models


def wrong_in_both_conditions(correct_dict, model, cve):
    """
    True if the model was incorrect in BOTH conditions for this CVE.
    If only one condition is present (data gap), treat as wrong — strict bar,
    same as attack_vector and CIA scripts.
    """
    results = list(correct_dict[model].get(cve, {}).values())
    return all(not v for v in results) if results else True


def main():
    if not os.path.exists(INPUT):
        raise SystemExit(
            f"Not found: {INPUT}\n"
            f"Run from the directory containing {INPUT}"
        )

    declined, correct, models = load_data(INPUT)

    # ── Overlap analysis ──────────────────────────────────────────────────────
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

    unique = {
        m: sorted(
            cve for cve in declined[m]
            if sum(1 for mm in models if cve in declined[mm]) == 1
        )
        for m in models
    }

    # ── Cross-reference for the highest-declining model ───────────────────────
    top = max(models, key=lambda m: len(declined[m]))
    others = [m for m in models if m != top]

    both_wrong = sum(
        1 for cve in declined[top]
        if all(wrong_in_both_conditions(correct, m, cve) for m in others)
    )
    both_right = sum(
        1 for cve in declined[top]
        if all(not wrong_in_both_conditions(correct, m, cve) for m in others)
    )
    mixed = len(declined[top]) - both_wrong - both_right

    # ── Report ────────────────────────────────────────────────────────────────
    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    out("Declines overlap analysis — vulnerability type")
    out("A CVE is 'declined' by a model if predicted_label is None in >=1 condition (pooled).")
    out("Correctness: layer_1_result == 'correct' (strict accuracy, same as summary table).")
    out("")

    out("Declined-CVE set size per model:")
    for m in models:
        out(f"  {m:<26} {len(declined[m])}")
    out("")

    out(f"Overlap across {len(models)} models:")
    for k in sorted(by_count, reverse=True):
        out(f"  declined by {k}: {len(by_count[k])} CVE(s)")
    if not all_declined:
        out("  (no declines recorded for any model on this entity)")
    out("")

    out(f"Shared hard core (declined by ALL {len(models)} models): {len(shared)} CVE(s)")
    for cve in sorted(shared):
        out(f"    {cve}")
    if not shared:
        out("    (none)")
    out("")

    out("Model-specific declines (declined by that model alone):")
    for m in models:
        out(f"  {m:<26} {len(unique[m])}")
        for cve in unique[m]:
            out(f"    {cve}")
    out("")

    if declined[top]:
        out(f"Cross-reference: on the {len(declined[top])} CVE(s) {top} declined,")
        out(f"how did the other models perform? ('wrong' = incorrect in BOTH conditions)")
        out(f"  both other models also wrong: {both_wrong}")
        out(f"  both other models correct:    {both_right}")
        out(f"  mixed:                        {mixed}")
    else:
        out("No declines recorded — cross-reference not applicable.")
    out("")

    out("Reading:")
    out("  A large shared hard core points to genuinely hard CVE descriptions (a data")
    out("  property). A large model-specific count points to a behavioural difference")
    out("  (that model is simply more willing to abstain on this entity). Compare")
    out("  this result against the attack_vector and CIA decline analyses to determine")
    out("  whether abstention patterns are consistent across entities or entity-specific.")

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    with open(RESULTS_PATH, "w") as f:
        json.dump({
            "entity": "vulnerability_type",
            "source_file": INPUT,
            "correctness_definition": "layer_1_result == correct",
            "decline_definition": "predicted_label is None in >=1 condition (pooled)",
            "wrong_definition": "incorrect in both conditions",
            "declined_count_per_model": {m: len(declined[m]) for m in models},
            "overlap_by_count": {str(k): sorted(v) for k, v in by_count.items()},
            "shared_all_models": sorted(shared),
            "unique_per_model": unique,
            "cross_reference_top_decliner": {
                "model": top,
                "n_declined": len(declined[top]),
                "both_others_wrong": both_wrong,
                "both_others_correct": both_right,
                "mixed": mixed,
            },
        }, f, indent=2)

    print(f"\nWritten: {REPORT_PATH}")
    print(f"Written: {RESULTS_PATH}")


if __name__ == "__main__":
    main()