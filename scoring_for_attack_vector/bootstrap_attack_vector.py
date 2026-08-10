"""
Bootstrap confidence intervals - attack vector.

Run from cve-ner-dissertation/scoring_for_attack_vector/
    python bootstrap_attack_vector.py

Reads : ../ultimate_dataset/merging_results.json
Writes: bootstrap_attack_vector_report.txt
        bootstrap_attack_vector_results.json

Requires: nothing beyond the standard library.

What it does
------------
A point F1 is one number from one sample of 500 CVEs. The bootstrap estimates
how much that number would wobble under a different sample, WITHOUT collecting
new data: it resamples the 500 CVEs with replacement many times, recomputes F1
on each resample, and takes the middle 95% of those values as the confidence
interval.

Design decisions
----------------
1. Resampling is at the CVE level (whole CVEs are drawn, carrying their
   outcome), not the row level - the CVE is the unit of observation.
2. The SAME resampled CVE indices are used across all six cells within each
   iteration, so intervals are mutually consistent. (Implemented by drawing one
   index list per iteration and applying it to every cell.)
3. Two macro-F1 variants are reported:
     - macro over all four classes (honest headline, but inflated variance
       because PHYSICAL n=3 and ADJACENT_NETWORK n=10 swing wildly);
     - macro over the well-supported classes only (NETWORK, LOCAL), which is
       far more precise and aligns with the paired significance testing.
   Both are reported; neither is hidden.
4. Percentile method for the interval (2.5th / 97.5th). Simple, assumption-free,
   standard for this use.

The wide interval on rare classes is a deliberate, honest output: it shows the
instability that a point estimate hides, rather than asserting it in a footnote.
"""

import json
import os
import random
from collections import defaultdict

ENTITY = "attack_vector"
CLASSES = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]
WELL_SUPPORTED = ["NETWORK", "LOCAL"]   # classes with enough n for a stable mean

INPUT = os.path.join("..", "ultimate_dataset", "merging_results.json")
N_BOOT = 5000
SEED = 42


def normalise(value):
    if not isinstance(value, str):
        return None
    label = "_".join(value.strip().strip(".,;:").lower().split()).replace("-", "_").upper()
    return label if label in CLASSES else None


def load_cells(path):
    """Return {(model, condition): {cve_id: (predicted_or_None, ground_truth)}} and sorted cve list."""
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    cells = defaultdict(dict)
    cve_ids = set()
    for r in rows:
        key = (r["model"], r["prompt_condition"])
        gt = r["ground_truth"].get(ENTITY)
        pred = normalise(r["extracted"].get(ENTITY))
        cells[key][r["cve_id"]] = (pred, gt)
        cve_ids.add(r["cve_id"])
    return cells, sorted(cve_ids)


def f1_scores(pairs):
    """Return {class: f1} from a list of (pred, gt) pairs."""
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)
    for pred, gt in pairs:
        if pred == gt:
            tp[gt] += 1
        else:
            fn[gt] += 1
            if pred is not None:
                fp[pred] += 1
    out = {}
    for c in CLASSES:
        p = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else 0.0
        r = tp[c] / (tp[c] + fn[c]) if (tp[c] + fn[c]) else 0.0
        out[c] = 2 * p * r / (p + r) if (p + r) else 0.0
    return out


def macro(f1s, classes):
    return sum(f1s[c] for c in classes) / len(classes)


def percentile_ci(values, lo=0.025, hi=0.975):
    s = sorted(values)
    return s[int(lo * len(s))], s[int(hi * len(s))]


def bootstrap(cells, cve_ids):
    n = len(cve_ids)
    rng = random.Random(SEED)

    # Point estimates (full sample).
    point = {}
    for key, by_cve in cells.items():
        f1s = f1_scores([by_cve[c] for c in cve_ids])
        point[key] = {
            "per_class_f1": f1s,
            "macro_all": macro(f1s, CLASSES),
            "macro_supported": macro(f1s, WELL_SUPPORTED),
        }

    # Bootstrap distributions.
    dist = {key: {"macro_all": [], "macro_supported": [],
                  **{c: [] for c in CLASSES}} for key in cells}

    for _ in range(N_BOOT):
        idx = [rng.randrange(n) for _ in range(n)]      # shared across cells
        sampled_cves = [cve_ids[i] for i in idx]
        for key, by_cve in cells.items():
            f1s = f1_scores([by_cve[c] for c in sampled_cves])
            dist[key]["macro_all"].append(macro(f1s, CLASSES))
            dist[key]["macro_supported"].append(macro(f1s, WELL_SUPPORTED))
            for c in CLASSES:
                dist[key][c].append(f1s[c])

    # Assemble results with CIs.
    results = {}
    for key in cells:
        support = {c: sum(1 for cv in cve_ids if cells[key][cv][1] == c) for c in CLASSES}
        ci_all = percentile_ci(dist[key]["macro_all"])
        ci_sup = percentile_ci(dist[key]["macro_supported"])
        per_class = {}
        for c in CLASSES:
            lo, hi = percentile_ci(dist[key][c])
            per_class[c] = {
                "support": support[c],
                "f1": point[key]["per_class_f1"][c],
                "ci_low": lo, "ci_high": hi,
            }
        results[key] = {
            "macro_all": {"point": point[key]["macro_all"],
                          "ci_low": ci_all[0], "ci_high": ci_all[1]},
            "macro_supported": {"point": point[key]["macro_supported"],
                                "ci_low": ci_sup[0], "ci_high": ci_sup[1]},
            "per_class": per_class,
        }
    return results


def write_report(results, path):
    lines = []
    def out(s=""):
        print(s)
        lines.append(s)

    out(f"Bootstrap confidence intervals - {ENTITY}")
    out(f"{N_BOOT} resamples, CVE-level, percentile method, seed {SEED}")
    out("")
    out("Two macro-F1 variants per cell:")
    out("  all-class     = mean over NETWORK, ADJACENT_NETWORK, LOCAL, PHYSICAL")
    out("                  (honest headline; wide because two classes are tiny)")
    out("  supported     = mean over NETWORK and LOCAL only")
    out("                  (precise; aligns with the paired significance tests)")
    out("")

    out(f"{'cell':32}{'macro(all)':>13}{'95% CI':>18}{'macro(sup)':>13}{'95% CI':>18}")
    out("-" * 94)
    for key in sorted(results):
        r = results[key]
        label = f"{key[0]} [{key[1]}]"
        a = r["macro_all"]; s = r["macro_supported"]
        out(f"{label:32}{a['point']:13.3f}   [{a['ci_low']:.3f}, {a['ci_high']:.3f}]"
            f"{s['point']:13.3f}   [{s['ci_low']:.3f}, {s['ci_high']:.3f}]")

    out("")
    out("Per-class F1 with 95% CI (all cells)")
    out("Note the width on ADJACENT_NETWORK (n=10) and PHYSICAL (n=3): these")
    out("intervals are the honest measure of how little those scores can be trusted.")
    out("")
    for key in sorted(results):
        out(f"  {key[0]} [{key[1]}]")
        out(f"    {'class':20}{'n':>4}{'F1':>8}{'95% CI':>20}")
        for c in CLASSES:
            m = results[key]["per_class"][c]
            out(f"    {c:20}{m['support']:4}{m['f1']:8.3f}   "
                f"[{m['ci_low']:.3f}, {m['ci_high']:.3f}]")
        out("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    if not os.path.exists(INPUT):
        raise SystemExit(f"Not found: {INPUT}\nRun from scoring_for_attack_vector/.")

    cells, cve_ids = load_cells(INPUT)
    results = bootstrap(cells, cve_ids)
    write_report(results, "bootstrap_attack_vector_report.txt")

    serialisable = {f"{m}|{c}": v for (m, c), v in results.items()}
    with open("bootstrap_attack_vector_results.json", "w") as f:
        json.dump({
            "entity": ENTITY,
            "n_bootstrap": N_BOOT,
            "seed": SEED,
            "method": "percentile, CVE-level resampling",
            "well_supported_classes": WELL_SUPPORTED,
            "cells": serialisable,
        }, f, indent=2)

    print("\nWritten: bootstrap_attack_vector_report.txt")
    print("Written: bootstrap_attack_vector_results.json")


if __name__ == "__main__":
    main()