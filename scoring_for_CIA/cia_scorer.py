"""
CIA Impact Scorer
=================
Scores LLM-extracted Confidentiality / Integrity / Availability impact values
against CVSS v3.x ground truth.

This uses EXACTLY the same five-category outcome scheme as the locked
attack_vector scorer, applied independently to each of the three CIA
components. Where attack_vector scores one entity across 6 cells (3 models x
2 conditions), this scores three entities (confidentiality_impact,
integrity_impact, availability_impact) across 18 cells (3 components x 3
models x 2 conditions) - same scheme, same category definitions, same
scoring rule, just run three times.

USAGE
-----
Place this script in:   cve-ner-dissertation/scoring_for_CIA/
Input is read from:     cve-ner-dissertation/ultimate_dataset/merging_results.json
Outputs are written to: cve-ner-dissertation/scoring_for_CIA/outputs/

    cd cve-ner-dissertation/scoring_for_CIA
    python cia_scorer.py

Requires: nothing beyond the standard library.


METHODOLOGY DECISIONS (identical wording/logic to attack_vector, by design)
-----------------------------------------------------------------------------
1. INDEPENDENT SCORING
   Confidentiality, Integrity and Availability are scored as three separate
   3-class classification problems (classes: NONE / LOW / HIGH). They are
   never collapsed into a single combined "CIA score". Prior work reported
   CIA as part of an aggregate CVSS vector and so could not identify which
   impact metric was responsible for poor performance. Scoring each
   independently is the central methodological choice of this study.

2. FIVE OUTCOME CATEGORIES (same scheme as attack_vector)
   Each extraction is assigned to one of five outcome categories:

     Correct    extracted value maps to the ground truth class
     Incorrect  maps to a valid class, but not the ground truth
     Unmapped   returned text that maps to none of NONE/LOW/HIGH
     Declined   well-formed response, no value assigned for this component
     Malformed  response could not be parsed / record shape unusable

   Counting:
     Correct    -> TP for ground truth class
     Incorrect  -> FP for predicted class, FN for ground truth class
     Unmapped   -> FN for ground truth class, no FP
     Declined   -> FN for ground truth class, no FP
     Malformed  -> FN for ground truth class, no FP

   Correct and Incorrect extractions are counted as a true positive / a
   false-positive-plus-false-negative pair respectively. The remaining three
   categories are treated identically for scoring purposes: each is counted
   as a false negative for the ground truth class with no false positive
   recorded, on the basis that a model producing no usable value has missed
   a true case without asserting anything incorrect. Although scored
   identically, these three categories are recorded and reported SEPARATELY
   so the reason for a missing prediction remains visible - this is the
   exact rationale attack_vector's Methodology text already states, and it
   is not restated per-entity, only applied.

   Malformed is a real, tested code path (checks whether the `extracted`
   block is a dict and contains the component's key at all), not an
   assumed zero - same principle as attack_vector's Malformed check, which
   exists even though every row in this dataset has valid: true.

3. HEADLINE METRIC: MACRO-AVERAGED F1
   Precision, recall and F1 are computed per class, then averaged with equal
   weight (macro, not micro). LOW is the minority class (~600 of 3000 rows
   per component); micro-averaging weights by class frequency and would
   allow good performance on NONE and HIGH to mask failure on LOW.
   Macro-averaging gives each class an equal vote, making per-class weakness
   visible. Exact-match accuracy is reported alongside as a secondary figure,
   not led with - same convention as attack_vector.

4. RECORDS RETAINED IN THE DENOMINATOR
   Every model x condition x component cell is scored over all 500 CVEs,
   never a reduced count. Excluding non-committal rows would compute scores
   over a smaller n for models that decline more often, systematically
   flattering the least reliable model. Retaining them keeps every cell
   directly comparable at n=500. The rate of missing predictions (Unmapped +
   Declined + Malformed) is reported per cell alongside precision/recall/F1
   rather than being represented solely through depressed recall.

5. ZERO-DENOMINATOR PRECISION
   Defined as 0.0 and flagged explicitly (precision_undefined = True) rather
   than reported as NaN or silently omitted.

6. NORMALISATION
   Case-insensitive, whitespace-stripped. Ground truth is emitted as
   'HIGH'/'LOW'/'NONE'; extractions as 'High'/'Low'/'None'/null. Single-letter
   CVSS shorthand (H/L/N) is also accepted defensively, though not present in
   the current data. Deliberately conservative, matching attack_vector's
   normalisation philosophy: anything that does not land exactly on one of
   the three classes goes to Unmapped rather than being coerced by substring
   matching.
   IMPORTANT: the string 'None' (the model asserts no impact) and JSON null
   (the model gave no answer) are semantically distinct and are never
   conflated - null is checked before any string handling, so this
   distinction cannot be lost.


OUTPUTS
-------
  outputs/cia_scores.csv      headline metrics per component x model x condition
  outputs/cia_per_class.csv   per-class precision / recall / F1 / support
  outputs/cia_confusion.csv   confusion matrix counts, long format (includes
                               Unmapped/Declined/Malformed as explicit columns,
                               not a single collapsed NULL sentinel)
  outputs/cia_outcomes.csv    outcome-category breakdown per cell (NEW - the
                               direct equivalent of attack_vector's Outcomes
                               sheet)
  outputs/cia_long.csv        one row per CVE x model x condition x component,
                               with outcome, predicted, truth, correct - the
                               row-level detail needed for McNemar's test
  outputs/cia_summary.txt     readable report of all of the above
"""

import json
import os
from collections import Counter, defaultdict

RESULTS_PATH = os.path.join("..", "ultimate_dataset", "merging_results.json")
OUT_DIR = "outputs"

COMPONENTS = [
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]

# The three real classes, fixed order: every table reads NONE -> LOW -> HIGH.
CLASSES = ["NONE", "LOW", "HIGH"]

# Outcome categories, in reporting order - identical set to attack_vector.
OUTCOMES = ["Correct", "Incorrect", "Unmapped", "Declined", "Malformed"]

UNDEFINED_PRECISION = 0.0


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def normalise(value):
    """
    Map a raw impact value to 'NONE' / 'LOW' / 'HIGH', or None if unmappable.

    Conservative by design, matching attack_vector: anything that does not
    land exactly on a known class returns None (Unmapped) rather than being
    coerced.
    """
    if not isinstance(value, str):
        return None

    cleaned = value.strip().upper()
    if cleaned in CLASSES:
        return cleaned

    # Defensive: single-letter CVSS shorthand. Not present in the current
    # data, but handled so a future re-run cannot silently drop values.
    return {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(cleaned)


# ---------------------------------------------------------------------------
# Classification - one record, one component, one outcome
# ---------------------------------------------------------------------------
def classify(record, component):
    """
    Assign one outcome category to a single record for a single CIA component.

    Returns (outcome, predicted_class_or_None, ground_truth_class_or_None).

    Mirrors attack_vector's classify() exactly:
      - Malformed: extracted block missing / not a dict / key absent
      - Declined:  key present, value is JSON null
      - Unmapped:  value present, non-null, but doesn't map to a class
      - Correct / Incorrect: value maps to a class, compared to ground truth
    """
    ground_truth = normalise((record.get("ground_truth") or {}).get(component))

    extracted_block = record.get("extracted")
    if not isinstance(extracted_block, dict) or component not in extracted_block:
        return "Malformed", None, ground_truth

    raw = extracted_block.get(component)
    if raw is None:
        return "Declined", None, ground_truth

    predicted = normalise(raw)
    if predicted is None:
        return "Unmapped", None, ground_truth

    if predicted == ground_truth:
        return "Correct", predicted, ground_truth
    return "Incorrect", predicted, ground_truth


# ---------------------------------------------------------------------------
# Scoring - one (component, model, condition) cell
# ---------------------------------------------------------------------------
def score_cell(records, component):
    """Compute counts and metrics for one component x model x condition cell."""
    tp = Counter()
    fp = Counter()
    fn = Counter()
    support = Counter()
    outcomes = Counter()
    confusion = defaultdict(Counter)  # ground_truth -> predicted_class/outcome
    long_rows = []

    for record in records:
        outcome, predicted, ground_truth = classify(record, component)
        outcomes[outcome] += 1
        if ground_truth is not None:
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
            if ground_truth is not None:
                fn[ground_truth] += 1
                confusion[ground_truth][outcome] += 1

        long_rows.append({
            "cve_id": record.get("cve_id"),
            "component": component,
            "outcome": outcome,
            # predicted stays a UNIFORM sentinel for the three no-value outcomes,
            # since they're scored identically (FN, no FP) - matches the <NULL>
            # sentinel bootstrap_cia.py/mcnemar_cia.py already expect. The fine
            # distinction (which of the three) lives in the 'outcome' column,
            # not here, so downstream scripts don't need to change.
            "predicted": predicted if predicted is not None else "<NULL>",
            "truth": ground_truth,
            "correct": outcome == "Correct",
        })

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
    commit_rate = (total - no_prediction) / total if total else float("nan")

    return {
        "n": total,
        "outcomes": dict(outcomes),
        "per_class": per_class,
        "macro_f1": macro_f1,
        "accuracy": accuracy,
        "commit_rate": commit_rate,
        "no_prediction_rate": no_prediction / total if total else float("nan"),
        "confusion": confusion,
    }, long_rows


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------
def load_records(path):
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Could not find results file at: {os.path.abspath(path)}\n"
            "Expected layout:\n"
            "  cve-ner-dissertation/ultimate_dataset/merging_results.json\n"
            "  cve-ner-dissertation/scoring_for_CIA/cia_scorer.py  <- run from here"
        )
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def run_all(records):
    """Score every component x model x condition cell. 3 x 3 x 2 = 18 cells."""
    by_cell = defaultdict(list)
    for r in records:
        by_cell[(r.get("model"), r.get("prompt_condition"))].append(r)

    cells = {}
    all_long_rows = []
    for (model, condition), cell_records in sorted(by_cell.items()):
        for comp in COMPONENTS:
            result, long_rows = score_cell(cell_records, comp)
            cells[f"{comp}|{model}|{condition}"] = {
                "component": comp, "model": model, "condition": condition, **result,
            }
            for row in long_rows:
                row["model"] = model
                row["condition"] = condition
            all_long_rows.extend(long_rows)

    return cells, all_long_rows


# ---------------------------------------------------------------------------
# CSV writers (no pandas dependency, matching attack_vector's stdlib-only style)
# ---------------------------------------------------------------------------
def write_csv(path, header, rows):
    import csv
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def write_scores_csv(cells, path):
    rows = []
    for key in sorted(cells):
        c = cells[key]
        rows.append([
            c["component"], c["model"], c["condition"],
            round(c["macro_f1"], 4), round(c["accuracy"], 4), round(c["commit_rate"], 4),
            c["n"], c["outcomes"].get("Unmapped", 0), c["outcomes"].get("Declined", 0),
            c["outcomes"].get("Malformed", 0),
        ])
    write_csv(path, ["component", "model", "condition", "macro_f1", "accuracy",
                      "commit_rate", "n", "n_unmapped", "n_declined", "n_malformed"], rows)


def write_outcomes_csv(cells, path):
    rows = []
    for key in sorted(cells):
        c = cells[key]
        o = c["outcomes"]
        rows.append([c["component"], c["model"], c["condition"]] +
                     [o.get(cat, 0) for cat in OUTCOMES])
    write_csv(path, ["component", "model", "condition"] + OUTCOMES, rows)


def write_per_class_csv(cells, path):
    rows = []
    for key in sorted(cells):
        c = cells[key]
        for cls in CLASSES:
            d = c["per_class"][cls]
            rows.append([
                c["component"], c["model"], c["condition"], cls,
                round(d["precision"], 4), round(d["recall"], 4), round(d["f1"], 4),
                d["support"], d["tp"], d["fp"], d["fn"], d["precision_undefined"],
            ])
    write_csv(path, ["component", "model", "condition", "class", "precision", "recall",
                      "f1", "support", "tp", "fp", "fn", "precision_undefined"], rows)


def write_confusion_csv(cells, path):
    rows = []
    for key in sorted(cells):
        c = cells[key]
        for true_cls, predicted_counter in c["confusion"].items():
            for predicted, count in predicted_counter.items():
                rows.append([c["component"], c["model"], c["condition"], true_cls, predicted, count])
    write_csv(path, ["component", "model", "condition", "true", "predicted", "count"], rows)


def write_long_csv(long_rows, path):
    rows = [[r["cve_id"], r["model"], r["condition"], r["component"], r["outcome"],
             r["predicted"], r["truth"], r["correct"]] for r in long_rows]
    write_csv(path, ["cve_id", "model", "condition", "component", "outcome",
                      "predicted", "truth", "correct"], rows)


# ---------------------------------------------------------------------------
# Human-readable report
# ---------------------------------------------------------------------------
def build_report(cells, n_records):
    lines = []
    add = lines.append

    add("=" * 90)
    add("CIA IMPACT SCORING")
    add("=" * 90)
    add(f"Records: {n_records}   Cells: {len(cells)} (3 components x 3 models x 2 conditions)")
    add("Outcome scheme: Correct / Incorrect / Unmapped / Declined / Malformed")
    add("(identical scheme and scoring rule to attack_vector; Malformed is a measured, not")
    add(" asserted, zero - it checks record shape, same as attack_vector's check.)")
    add("")

    add("-" * 90)
    add("1. OUTCOME BREAKDOWN per cell")
    add("-" * 90)
    add(f"{'component':<24}{'model':<20}{'condition':<12}" + "".join(f"{o:<11}" for o in OUTCOMES))
    for key in sorted(cells):
        c = cells[key]
        o = c["outcomes"]
        add(f"{c['component']:<24}{c['model']:<20}{c['condition']:<12}" +
            "".join(f"{o.get(cat, 0):<11}" for cat in OUTCOMES))
    add("")

    add("-" * 90)
    add("2. MACRO-F1  [PRIMARY METRIC]   (accuracy and commit_rate reported alongside)")
    add("-" * 90)
    add(f"{'component':<24}{'model':<20}{'condition':<12}{'macro_f1':<10}{'accuracy':<10}{'commit_rate':<12}")
    for key in sorted(cells):
        c = cells[key]
        add(f"{c['component']:<24}{c['model']:<20}{c['condition']:<12}"
            f"{c['macro_f1']:<10.3f}{c['accuracy']:<10.3f}{c['commit_rate']:<12.3f}")
    add("")

    add("-" * 90)
    add("3. PER-CLASS F1")
    add("-" * 90)
    add(f"{'component':<24}{'model':<20}{'condition':<12}{'class':<6}{'precision':<11}{'recall':<9}{'f1':<8}{'support'}")
    for key in sorted(cells):
        c = cells[key]
        for cls in CLASSES:
            d = c["per_class"][cls]
            add(f"{c['component']:<24}{c['model']:<20}{c['condition']:<12}{cls:<6}"
                f"{d['precision']:<11.3f}{d['recall']:<9.3f}{d['f1']:<8.3f}{d['support']}")
    add("")

    return "\n".join(lines)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    records = load_records(RESULTS_PATH)
    cells, long_rows = run_all(records)

    write_scores_csv(cells, os.path.join(OUT_DIR, "cia_scores.csv"))
    write_outcomes_csv(cells, os.path.join(OUT_DIR, "cia_outcomes.csv"))
    write_per_class_csv(cells, os.path.join(OUT_DIR, "cia_per_class.csv"))
    write_confusion_csv(cells, os.path.join(OUT_DIR, "cia_confusion.csv"))
    write_long_csv(long_rows, os.path.join(OUT_DIR, "cia_long.csv"))

    report = build_report(cells, len(records))
    with open(os.path.join(OUT_DIR, "cia_summary.txt"), "w", encoding="utf-8") as fh:
        fh.write(report)

    print(report)
    print(f"\nWritten to {os.path.abspath(OUT_DIR)}/")


if __name__ == "__main__":
    main()