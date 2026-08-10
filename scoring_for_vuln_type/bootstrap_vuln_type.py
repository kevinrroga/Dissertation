"""
Bootstrap confidence intervals — vulnerability type.

Run from cve-ner-dissertation/scoring_for_vulnerability_type/
    python bootstrap_vulnerability_type.py

Reads : vulnerability_type_pillar_scored_details.json
Writes: bootstrap_vulnerability_type_report.txt
        bootstrap_vulnerability_type_results.json

Requires: nothing beyond the standard library.

What it does
------------
A point accuracy (correct / 500) is one number from one sample of 500 CVEs.
The bootstrap estimates how much that number would vary under a different
sample, without collecting new data: it resamples the 500 CVEs with
replacement 5,000 times, recomputes accuracy on each resample, and takes the
2.5th / 97.5th percentiles of those values as the 95% confidence interval.

Design decisions (matching attack_vector and CIA bootstrap exactly):
    1. Resampling is at the CVE level — whole CVEs are drawn, carrying their
       correct/incorrect outcome. The CVE is the unit of observation.
    2. The SAME resampled CVE indices are applied across all six cells within
       each bootstrap iteration, so the six intervals are mutually consistent
       and directly comparable.
    3. Percentile method (2.5th / 97.5th). Simple, assumption-free, standard
       for this use. Same method as attack_vector and CIA.
    4. 5,000 resamples, seed 42. Identical to both prior scripts.

ONE DELIBERATE DIFFERENCE FROM ATTACK_VECTOR:
    Attack vector reported two macro-F1 variants (all-class and supported-only)
    because PHYSICAL (n=3) and ADJACENT_NETWORK (n=10) were tiny and inflated
    variance. CIA reported one macro-F1 because all three classes had real
    support. Vulnerability type does not use F1 at all — it uses strict
    accuracy (correct/total). There is therefore no class-split decision to
    make. One accuracy CI per cell is reported, plus a breakdown by error
    category (same_pillar_wrong_cwe, consequence_not_mechanism,
    different_pillar, unmapped_or_absent) to show what drives incorrect
    predictions.

    The error category breakdown is bootstrapped too, giving CIs on the
    proportion of incorrect predictions falling into each category. This is
    new relative to attack_vector and CIA — it is possible here because the
    scored details file carries layer_2_error_category for every record.
"""

import json
import os
import random
from collections import defaultdict, Counter

INPUT = "vulnerability_type_pillar_scored_details.json"
REPORT_PATH = "bootstrap_vulnerability_type_report.txt"
RESULTS_PATH = "bootstrap_vulnerability_type_results.json"

MODELS = ["claude-sonnet-4.6", "deepseek-v4-pro", "gpt-5.5"]
CONDITIONS = ["zero_shot", "few_shot"]
ERROR_CATEGORIES = [
    "same_pillar_wrong_cwe",
    "consequence_not_mechanism",
    "different_pillar",
    "unmapped_or_absent",
]

N_BOOT = 5000
SEED = 42


def load_cells(path):
    """
    Return:
      cells: {(model, condition): {cve_id: {"correct": bool, "error_cat": str|None}}}
      cve_ids: sorted list of all unique CVE IDs
    """
    with open(path, encoding="utf-8") as f:
        records = json.load(f)

    cells = {}
    cve_ids = set()

    for r in records:
        key = (r["model"], r["prompt_condition"])
        cells.setdefault(key, {})[r["cve_id"]] = {
            "correct": r["layer_1_result"] == "correct",
            "error_cat": r.get("layer_2_error_category"),
        }
        cve_ids.add(r["cve_id"])

    return cells, sorted(cve_ids)


def compute_stats(records):
    """
    records: list of {"correct": bool, "error_cat": str|None}
    Returns accuracy and error category proportions (among incorrect only).
    """
    n = len(records)
    n_correct = sum(1 for r in records if r["correct"])
    accuracy = n_correct / n if n else 0.0

    incorrect = [r for r in records if not r["correct"]]
    n_inc = len(incorrect)
    cat_props = {}
    for cat in ERROR_CATEGORIES:
        cat_props[cat] = sum(1 for r in incorrect if r["error_cat"] == cat) / n_inc if n_inc else 0.0

    return accuracy, cat_props


def percentile_ci(values, lo=0.025, hi=0.975):
    s = sorted(values)
    return s[int(lo * len(s))], s[int(hi * len(s)) - 1]


def bootstrap(cells, cve_ids):
    n = len(cve_ids)
    rng = random.Random(SEED)

    # Point estimates on full sample
    point = {}
    for key, by_cve in cells.items():
        records = [by_cve[cve] for cve in cve_ids]
        acc, cat_props = compute_stats(records)
        point[key] = {"accuracy": acc, "error_category_proportions": cat_props}

    # Bootstrap distributions
    dist = {
        key: {"accuracy": [], **{cat: [] for cat in ERROR_CATEGORIES}}
        for key in cells
    }

    for _ in range(N_BOOT):
        # Same indices across all cells this iteration
        idx = [rng.randrange(n) for _ in range(n)]
        sampled_cves = [cve_ids[i] for i in idx]

        for key, by_cve in cells.items():
            records = [by_cve[cve] for cve in sampled_cves]
            acc, cat_props = compute_stats(records)
            dist[key]["accuracy"].append(acc)
            for cat in ERROR_CATEGORIES:
                dist[key][cat].append(cat_props[cat])

    # Assemble results with CIs
    results = {}
    for key in cells:
        acc_lo, acc_hi = percentile_ci(dist[key]["accuracy"])
        cat_cis = {}
        for cat in ERROR_CATEGORIES:
            lo, hi = percentile_ci(dist[key][cat])
            cat_cis[cat] = {
                "point": point[key]["error_category_proportions"][cat],
                "ci_low": lo,
                "ci_high": hi,
            }
        results[key] = {
            "accuracy": {
                "point": point[key]["accuracy"],
                "ci_low": acc_lo,
                "ci_high": acc_hi,
            },
            "error_category_proportions": cat_cis,
        }

    return results


def write_report(results, path):
    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    out("Bootstrap confidence intervals — vulnerability type")
    out(f"{N_BOOT} resamples, CVE-level, percentile method, seed {SEED}")
    out("Metric: strict accuracy (correct CWE resolved / total).")
    out("Error category proportions are among incorrect predictions only.")
    out("")

    # Accuracy table
    out(f"{'Cell':<36}{'Accuracy':>10}{'95% CI':>22}")
    out("-" * 70)
    for model in MODELS:
        for condition in CONDITIONS:
            key = (model, condition)
            r = results[key]["accuracy"]
            label = f"{model} [{condition}]"
            out(f"{label:<36}{r['point']:>10.3f}   [{r['ci_low']:.3f}, {r['ci_high']:.3f}]")
    out("")

    # Error category breakdown
    out("Error category proportions (among incorrect predictions) with 95% CI")
    out("Proportions sum to 1.0 within each cell.")
    out("")
    for model in MODELS:
        for condition in CONDITIONS:
            key = (model, condition)
            label = f"{model} [{condition}]"
            out(f"  {label}")
            out(f"    {'Category':<30}{'Proportion':>12}{'95% CI':>22}")
            for cat in ERROR_CATEGORIES:
                r = results[key]["error_category_proportions"][cat]
                out(f"    {cat:<30}{r['point']:>12.3f}   [{r['ci_low']:.3f}, {r['ci_high']:.3f}]")
            out("")

    out("Interpretation:")
    out("  Overlapping CIs between two cells = no reliable accuracy difference.")
    out("  same_pillar_wrong_cwe dominates across all cells — models identify")
    out("  the correct vulnerability family but land on the wrong specific CWE.")
    out("  consequence_not_mechanism = model named an impact (e.g. Denial of")
    out("  Service) rather than the root cause mechanism — a qualitatively")
    out("  different error from wrong-CWE within the same family.")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    if not os.path.exists(INPUT):
        raise SystemExit(
            f"Not found: {INPUT}\n"
            f"Run from the directory containing vulnerability_type_pillar_scored_details.json"
        )

    cells, cve_ids = load_cells(INPUT)
    results = bootstrap(cells, cve_ids)
    write_report(results, REPORT_PATH)

    serialisable = {f"{m}|{c}": v for (m, c), v in results.items()}
    with open(RESULTS_PATH, "w") as f:
        json.dump({
            "entity": "vulnerability_type",
            "n_bootstrap": N_BOOT,
            "seed": SEED,
            "method": "percentile, CVE-level resampling",
            "metric": "strict_accuracy",
            "error_categories": ERROR_CATEGORIES,
            "cells": serialisable,
        }, f, indent=2)

    print(f"\nWritten: {REPORT_PATH}")
    print(f"Written: {RESULTS_PATH}")


if __name__ == "__main__":
    main()