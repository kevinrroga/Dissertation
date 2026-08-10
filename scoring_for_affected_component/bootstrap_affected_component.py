"""
Bootstrap confidence intervals — affected component.

Run from cve-ner-dissertation/scoring_for_affected_component/
    python bootstrap_affected_component.py

Reads : outputs/affected_component_long.csv   (from score_affected_component.py)
Writes: outputs/bootstrap_affected_component_report.txt
        outputs/bootstrap_affected_component_results.json

Requires: nothing beyond the standard library.

METHOD
------
Affected component has no closed class set, so macro-F1 over classes is not
applicable here. The headline metric is binary accuracy (match / n), which
equals recall under the FP=0 policy established in the scorer. The bootstrap
estimates how much that accuracy would vary under a different sample, without
collecting new data: it resamples the 500 CVEs with replacement 5,000 times,
recomputes accuracy on each resample, and takes the 2.5th/97.5th percentiles
as the 95% CI.

DESIGN DECISIONS (explicit, for the Methodology chapter)
---------------------------------------------------------
1. Resampling unit: CVE. Whole CVEs are drawn with replacement, carrying
   their matched/not-matched outcome. This is the same unit as attack_vector
   and CIA, so the three entities are directly comparable in method.

2. Shared index draws: the SAME 500 resampled CVE indices are applied to all
   six cells within each bootstrap iteration. This makes CIs mutually
   consistent across cells (a given bootstrap world contains the same CVEs
   for every model/condition), directly supporting the McNemar paired design.

3. Resamples: 5,000. Same as attack_vector and CIA.

4. Seed: 42. Same as attack_vector and CIA.

5. Percentile method (2.5th / 97.5th). Assumption-free, standard for this
   use case, same as attack_vector and CIA.

6. Metric reported: accuracy (= recall = TP / (TP + FN) when FP = 0).
   F1 is also reported for cross-entity comparability, but since precision
   is always 1.0 under the FP=0 policy, F1 is a deterministic transformation
   of recall and adds no independent information. Both are stated explicitly
   to avoid any appearance of selectively reporting the more favourable
   number.

7. Partial matches: excluded from the positive class throughout (consistent
   with the scorer's headline metric). The partial rate is not bootstrapped
   separately; it is reported as a descriptive statistic in the main scorer
   output.
"""

import csv
import json
import random

IN_PATH = "outputs/affected_component_long.csv"
REPORT_PATH = "outputs/bootstrap_affected_component_report.txt"
RESULTS_PATH = "outputs/bootstrap_affected_component_results.json"

MODELS = ["claude-sonnet-4.6", "deepseek-v4-pro", "gpt-5.5"]
CONDITIONS = ["zero_shot", "few_shot"]

N_RESAMPLES = 5000
SEED = 42


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_long(path):
    """
    Returns:
      cells: {(model, condition): {cve_id: bool}}   True = matched
      cve_ids: sorted list of all CVE IDs
    """
    cells = {}
    cve_set = set()

    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key = (row["model"], row["condition"])
            cells.setdefault(key, {})[row["cve_id"]] = (
                row["matched"].strip().lower() == "true"
            )
            cve_set.add(row["cve_id"])

    return cells, sorted(cve_set)


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def accuracy(matched_list):
    """Binary accuracy from a list of booleans."""
    return sum(matched_list) / len(matched_list) if matched_list else 0.0


def f1_from_accuracy(acc):
    """
    Under FP=0 policy: precision = 1.0, recall = accuracy.
    F1 = 2 * precision * recall / (precision + recall) = 2 * acc / (1 + acc).
    """
    return 2 * acc / (1 + acc) if (1 + acc) > 0 else 0.0


def percentile_ci(values, lo=0.025, hi=0.975):
    s = sorted(values)
    return s[int(lo * len(s))], s[int(hi * len(s)) - 1]


def bootstrap(cells, cve_ids):
    n = len(cve_ids)
    rng = random.Random(SEED)

    # Point estimates on the full sample.
    point = {}
    for key, by_cve in cells.items():
        acc = accuracy([by_cve[c] for c in cve_ids])
        point[key] = {"accuracy": acc, "f1": f1_from_accuracy(acc)}

    # Bootstrap distributions — shared index draws across all cells.
    dist = {key: {"accuracy": [], "f1": []} for key in cells}

    for _ in range(N_RESAMPLES):
        idx = [rng.randrange(n) for _ in range(n)]
        sampled_cves = [cve_ids[i] for i in idx]
        for key, by_cve in cells.items():
            acc = accuracy([by_cve[c] for c in sampled_cves])
            dist[key]["accuracy"].append(acc)
            dist[key]["f1"].append(f1_from_accuracy(acc))

    # Assemble results with CIs.
    results = {}
    for key in cells:
        acc_ci = percentile_ci(dist[key]["accuracy"])
        f1_ci = percentile_ci(dist[key]["f1"])
        results[key] = {
            "n": n,
            "accuracy": {
                "point": point[key]["accuracy"],
                "ci_low": acc_ci[0],
                "ci_high": acc_ci[1],
            },
            "f1": {
                "point": point[key]["f1"],
                "ci_low": f1_ci[0],
                "ci_high": f1_ci[1],
            },
        }

    return results


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_report(results):
    lines = []
    add = lines.append

    add("=" * 90)
    add("Bootstrap 95% confidence intervals — affected component")
    add("=" * 90)
    add(f"{N_RESAMPLES} CVE-level resamples, percentile method, seed {SEED}.")
    add("")
    add("Metric: binary accuracy (= recall under the FP=0 policy).")
    add("F1 is reported for cross-entity comparability; it is a deterministic")
    add("transformation of accuracy when FP=0 (F1 = 2*acc / (1+acc)) and")
    add("adds no independent information.")
    add("Partial matches are excluded from the positive class throughout.")
    add("")
    add("-" * 90)
    add(f"{'Model':<25}{'Condition':<12}{'Accuracy':<10}{'95% CI (acc)':<22}"
        f"{'F1':<10}{'95% CI (F1)'}")
    add("-" * 90)

    for key in sorted(results):
        model, condition = key
        r = results[key]
        acc = r["accuracy"]
        f1 = r["f1"]
        add(
            f"{model:<25}{condition:<12}"
            f"{acc['point']:<10.3f}"
            f"[{acc['ci_low']:.3f}, {acc['ci_high']:.3f}]        "
            f"{f1['point']:<10.3f}"
            f"[{f1['ci_low']:.3f}, {f1['ci_high']:.3f}]"
        )

    add("")
    add("-" * 90)
    add("INTERPRETATION NOTE")
    add("-" * 90)
    add("Overlapping CIs between two cells indicate that the difference in")
    add("accuracy is consistent with sampling variation and should not be")
    add("interpreted as a reliable performance gap. The McNemar test provides")
    add("the formal paired significance test for each comparison.")
    add("")
    add("The relatively wide CIs here (compared to attack_vector and CIA)")
    add("reflect the genuine difficulty of this entity: 500 CVEs is sufficient")
    add("for the closed-class entities, but open-ended extraction accuracy")
    add("is more sensitive to which specific CVEs happen to be sampled.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    cells, cve_ids = load_long(IN_PATH)
    results = bootstrap(cells, cve_ids)

    report = build_report(results)
    print(report)

    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write(report)

    serialisable = {
        f"{m}|{c}": v for (m, c), v in results.items()
    }
    with open(RESULTS_PATH, "w", encoding="utf-8") as fh:
        json.dump({
            "entity": "affected_component",
            "n_bootstrap": N_RESAMPLES,
            "seed": SEED,
            "method": "percentile, CVE-level resampling, shared indices across cells",
            "metric": "binary accuracy (= recall under FP=0 policy)",
            "note": "F1 = 2*acc/(1+acc) when FP=0; reported for comparability only",
            "cells": serialisable,
        }, fh, indent=2)

    print(f"\nWritten: {REPORT_PATH}")
    print(f"Written: {RESULTS_PATH}")


if __name__ == "__main__":
    main()