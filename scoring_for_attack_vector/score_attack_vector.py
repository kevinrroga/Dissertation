"""
Attack vector scorer.

Run from cve-ner-dissertation/scoring_for_attack_vector/

Reads : ../ultimate_dataset/merging_results.json
Writes: score_attack_vector_report.txt    (human-readable tables)
        score_attack_vector_results.json  (machine-readable, for write-up/plots)

Scoring policy
--------------
Each extraction falls into one of five outcome categories:

  Correct    extracted value maps to the ground truth class
  Incorrect  maps to a valid class, but not the ground truth
  Unmapped   returned text that maps to none of the four classes
  Declined   well-formed response, no value assigned for this entity
  Malformed  response could not be parsed / record shape unusable

Counting:
  Correct    -> TP for ground truth class
  Incorrect  -> FP for predicted class, FN for ground truth class
  Unmapped   -> FN for ground truth class, no FP
  Declined   -> FN for ground truth class, no FP
  Malformed  -> FN for ground truth class, no FP

Records with no usable extraction are RETAINED in the denominator.
Every model-condition cell is scored over all 500 CVEs.
"""

import json
import os
import sys
from collections import Counter, defaultdict

ENTITY = "attack_vector"

DEFAULT_INPUT = os.path.join("..", "ultimate_dataset", "merging_results.json")
REPORT_TXT = "score_attack_vector_report.txt"
REPORT_JSON = "score_attack_vector_results.json"

# The four CVSS v3.x attack vector classes, in NVD long form.
CLASSES = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]

# Outcome categories, in reporting order.
OUTCOMES = ["Correct", "Incorrect", "Unmapped", "Declined", "Malformed"]

# Precision is undefined when a class is never predicted (TP+FP == 0).
# Convention: report as 0.0. Recorded here so the choice is explicit.
UNDEFINED_PRECISION = 0.0


# ---------------------------------------------------------------- normalisation

def normalise(value):
    """
    Map a raw extracted string onto one of CLASSES, or None if unmappable.

    Case-insensitive; strips whitespace and terminal punctuation; maps internal
    whitespace and hyphens to underscores. Deliberately conservative: anything
    that does not land exactly on a known class is left unmapped rather than
    coerced by substring matching (which would, for example, send
    "local network" to LOCAL).
    """
    if not isinstance(value, str):
        return None

    cleaned = value.strip().strip(".,;:").lower()
    cleaned = "_".join(cleaned.split())
    cleaned = cleaned.replace("-", "_")

    return cleaned.upper() if cleaned.upper() in CLASSES else None


# ---------------------------------------------------------------- classification

def classify(record):
    """
    Assign one outcome category to a single record.

    Returns (outcome, predicted_class_or_None, ground_truth_class).
    """
    ground_truth = record.get("ground_truth", {}).get(ENTITY)

    extracted_block = record.get("extracted")
    if not isinstance(extracted_block, dict) or ENTITY not in extracted_block:
        return "Malformed", None, ground_truth

    raw = extracted_block.get(ENTITY)
    if raw is None:
        return "Declined", None, ground_truth

    predicted = normalise(raw)
    if predicted is None:
        return "Unmapped", None, ground_truth

    if predicted == ground_truth:
        return "Correct", predicted, ground_truth
    return "Incorrect", predicted, ground_truth


# ---------------------------------------------------------------- metrics

def score_cell(records):
    """Compute counts and metrics for one model-condition cell."""
    tp = Counter()
    fp = Counter()
    fn = Counter()
    support = Counter()
    outcomes = Counter()
    confusion = defaultdict(Counter)   # ground truth -> predicted/outcome

    for record in records:
        outcome, predicted, ground_truth = classify(record)
        outcomes[outcome] += 1
        support[ground_truth] += 1

        if outcome == "Correct":
            tp[ground_truth] += 1
            confusion[ground_truth][predicted] += 1
        elif outcome == "Incorrect":
            fp[predicted] += 1
            fn[ground_truth] += 1
            confusion[ground_truth][predicted] += 1
        else:
            # Unmapped / Declined / Malformed: missed true case, no false claim.
            fn[ground_truth] += 1
            confusion[ground_truth][outcome] += 1

    per_class = {}
    for cls in CLASSES:
        p_denom = tp[cls] + fp[cls]
        r_denom = tp[cls] + fn[cls]

        precision = tp[cls] / p_denom if p_denom else UNDEFINED_PRECISION
        recall = tp[cls] / r_denom if r_denom else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        per_class[cls] = {
            "tp": tp[cls], "fp": fp[cls], "fn": fn[cls],
            "support": support[cls],
            "precision": precision, "recall": recall, "f1": f1,
            "precision_undefined": p_denom == 0,
        }

    total = len(records)
    macro_f1 = sum(per_class[c]["f1"] for c in CLASSES) / len(CLASSES)
    accuracy = outcomes["Correct"] / total if total else 0.0
    no_prediction = outcomes["Unmapped"] + outcomes["Declined"] + outcomes["Malformed"]

    # Sanity: every record contributes exactly one TP or one FN.
    checksum = sum(per_class[c]["tp"] + per_class[c]["fn"] for c in CLASSES)
    assert checksum == total, f"checksum {checksum} != {total} records"

    return {
        "n": total,
        "outcomes": {o: outcomes[o] for o in OUTCOMES},
        "per_class": per_class,
        "macro_f1": macro_f1,
        "accuracy": accuracy,
        "no_prediction_count": no_prediction,
        "no_prediction_rate": no_prediction / total if total else 0.0,
        "confusion": {gt: dict(row) for gt, row in confusion.items()},
    }


# ---------------------------------------------------------------- reporting

class Report:
    def __init__(self):
        self.lines = []

    def __call__(self, text=""):
        print(text)
        self.lines.append(text)

    def rule(self, title):
        self("")
        self(title)
        self("=" * len(title))

    def save(self, path):
        with open(path, "w") as f:
            f.write("\n".join(self.lines) + "\n")


def print_cell(out, model, condition, result):
    out.rule(f"{model}  |  {condition}")

    out(f"n = {result['n']}")
    out("")

    out("Outcomes")
    for outcome in OUTCOMES:
        count = result["outcomes"][outcome]
        pct = 100 * count / result["n"]
        out(f"  {outcome:12} {count:5}  ({pct:5.1f}%)")
    out("")

    out("Per class")
    out(f"  {'class':18} {'n':>4} {'TP':>5} {'FP':>5} {'FN':>5} "
        f"{'P':>7} {'R':>7} {'F1':>7}")
    for cls in CLASSES:
        m = result["per_class"][cls]
        flag = " *" if m["precision_undefined"] else ""
        out(f"  {cls:18} {m['support']:4} {m['tp']:5} {m['fp']:5} {m['fn']:5} "
            f"{m['precision']:7.3f} {m['recall']:7.3f} {m['f1']:7.3f}{flag}")
    if any(result["per_class"][c]["precision_undefined"] for c in CLASSES):
        out("  * class never predicted; precision undefined, reported as 0.000")
    out("")

    out(f"Macro-F1        {result['macro_f1']:.3f}")
    out(f"Accuracy        {result['accuracy']:.3f}")
    out(f"No prediction   {result['no_prediction_count']} "
        f"({100 * result['no_prediction_rate']:.1f}%)")


def print_summary(out, results):
    out.rule("SUMMARY — all cells")

    out(f"  {'model':22} {'condition':12} {'macro-F1':>9} {'accuracy':>9} "
        f"{'no-pred':>9}")
    for (model, condition), r in results.items():
        out(f"  {model:22} {condition:12} {r['macro_f1']:9.3f} "
            f"{r['accuracy']:9.3f} {100 * r['no_prediction_rate']:8.1f}%")

    out("")
    out("Per-class F1 across cells")
    header = f"  {'class':18}" + "".join(
        f"{m.split('-')[0][:8]:>10}" for m, _ in results
    )
    out(header)
    for cls in CLASSES:
        support = next(iter(results.values()))["per_class"][cls]["support"]
        line = f"  {cls:18}"
        for r in results.values():
            line += f"{r['per_class'][cls]['f1']:10.3f}"
        out(line + f"   (n={support})")

    out("")
    out("NOTE: classes with low support yield unstable F1. Interpret")
    out("ADJACENT_NETWORK and PHYSICAL as indicative only.")


# ---------------------------------------------------------------- main

def load(path):
    if not os.path.exists(path):
        raise SystemExit(
            f"Input file not found: {path}\n"
            "Run from scoring_for_attack_vector/, or pass a path:\n"
            "    python score_attack_vector.py /full/path/to/merging_results.json"
        )
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT
    rows = load(path)

    cells = defaultdict(list)
    for record in rows:
        cells[(record["model"], record["prompt_condition"])].append(record)

    out = Report()
    out(f"Attack vector scoring — {path}")
    out(f"records: {len(rows)}   cells: {len(cells)}")

    results = {}
    for key in sorted(cells):
        results[key] = score_cell(cells[key])
        print_cell(out, key[0], key[1], results[key])

    print_summary(out, results)

    out.save(REPORT_TXT)
    with open(REPORT_JSON, "w") as f:
        json.dump(
            {
                "entity": ENTITY,
                "input_file": os.path.abspath(path),
                "classes": CLASSES,
                "policy": {
                    "no_prediction_categories": ["Unmapped", "Declined", "Malformed"],
                    "no_prediction_treatment": "FN for ground truth class, no FP",
                    "denominator": "all records retained",
                    "undefined_precision": UNDEFINED_PRECISION,
                },
                "cells": {f"{m}|{c}": r for (m, c), r in results.items()},
            },
            f,
            indent=2,
        )

    print()
    print(f"Written: {REPORT_TXT}")
    print(f"Written: {REPORT_JSON}")


if __name__ == "__main__":
    main()