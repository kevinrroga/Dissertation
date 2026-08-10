"""
Bootstrap confidence intervals — CIA impact.

Run from cve-ner-dissertation/scoring_for_CIA/
    python bootstrap_cia.py

Reads : outputs/cia_long.csv   (from cia_scorer.py)
Writes: bootstrap_cia_report.txt
        bootstrap_cia_results.json

Requires: nothing beyond the standard library (same as attack_vector's version).

What it does
------------
A point macro-F1 is one number from one sample of 500 CVEs. Resampling those
500 CVEs with replacement, 5,000 times, and recomputing macro-F1 each time
gives a distribution — the 2.5th/97.5th percentiles of that distribution are
the 95% CI. Same method, same resample count (5,000) and seed (42) as
attack_vector, so the two are directly comparable in method if not in number.

ONE DELIBERATE DIFFERENCE FROM ATTACK_VECTOR, stated explicitly:
    Attack vector had two badly under-supported classes (PHYSICAL n=18,
    ADJACENT_NETWORK n=60 out of 500), so its bootstrap script reported BOTH
    an all-class macro-F1 (wide, rare-class-driven) and a "supported subset"
    macro-F1 restricted to NETWORK+LOCAL (tighter, matches the significance
    tests). CIA's three classes (NONE, LOW, HIGH) all have real support
    (100-227 per model/condition slice) - there is no comparably tiny class
    to exclude. So this script reports ONE macro-F1 CI per component, not two.
    The low-support per-class flag (< 20) is retained anyway, purely as a
    safety net in case a future re-run produces a thinner slice - it should
    not fire on the current data, and if it does, that itself is worth
    noticing before trusting the number.

Resampling unit: CVEs, not (model, condition, component) rows. For a fixed
model/condition/component, each bootstrap draws 500 CVE indices with
replacement and pulls that CVE's (predicted, truth) pair for every draw -
matching attack_vector's resampling unit exactly, so the two are comparable.
"""

import csv
import json
import random
from collections import defaultdict

IN_PATH = "outputs/cia_long.csv"
REPORT_PATH = "bootstrap_cia_report.txt"
RESULTS_PATH = "bootstrap_cia_results.json"

COMPONENTS = ["confidentiality_impact", "integrity_impact", "availability_impact"]
MODELS = ["claude-sonnet-4.6", "deepseek-v4-pro", "gpt-5.5"]
CONDITIONS = ["zero_shot", "few_shot"]
CLASSES = ["NONE", "LOW", "HIGH"]
NULL = "<NULL>"

N_RESAMPLES = 5000
SEED = 42
LOW_SUPPORT_THRESHOLD = 20


def load_long(path):
    """component -> (model, condition) -> list of (cve_id, predicted, truth)"""
    data = defaultdict(lambda: defaultdict(list))
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key = (row["model"], row["condition"])
            data[row["component"]][key].append(
                (row["cve_id"], row["predicted"], row["truth"])
            )
    return data


def macro_f1(pairs):
    """
    pairs: list of (predicted, truth). predicted may be NULL sentinel.
    Returns (macro_f1, accuracy, per_class dict of f1/support).
    """
    tp = defaultdict(int)
    fp = defaultdict(int)
    fn = defaultdict(int)
    correct = 0

    for pred, truth in pairs:
        if pred == truth:
            tp[truth] += 1
            correct += 1
        else:
            fn[truth] += 1
            if pred != NULL:
                fp[pred] += 1
            # NULL predictions: fn charged above, no fp charged (no class predicted)

    per_class = {}
    f1s = []
    for cls in CLASSES:
        support = sum(1 for _, truth in pairs if truth == cls)
        p = tp[cls] / (tp[cls] + fp[cls]) if (tp[cls] + fp[cls]) else 0.0
        r = tp[cls] / (tp[cls] + fn[cls]) if (tp[cls] + fn[cls]) else 0.0
        f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
        per_class[cls] = {"f1": f1, "support": support}
        f1s.append(f1)

    macro = sum(f1s) / len(f1s)
    accuracy = correct / len(pairs) if pairs else 0.0
    return macro, accuracy, per_class


def bootstrap_cell(pairs, n_resamples=N_RESAMPLES, seed=SEED):
    """
    pairs: list of (cve_id, predicted, truth) for one (component, model, condition).
    Resamples CVE indices with replacement, recomputes macro-F1 + per-class F1
    each time. Returns point estimate + percentile CIs.
    """
    rng = random.Random(seed)
    n = len(pairs)

    point_macro, point_acc, point_per_class = macro_f1([(p, t) for _, p, t in pairs])

    macro_samples = []
    per_class_samples = {cls: [] for cls in CLASSES}

    for _ in range(n_resamples):
        resample_idx = [rng.randrange(n) for _ in range(n)]
        resample_pairs = [(pairs[i][1], pairs[i][2]) for i in resample_idx]
        m, _, pc = macro_f1(resample_pairs)
        macro_samples.append(m)
        for cls in CLASSES:
            per_class_samples[cls].append(pc[cls]["f1"])

    def percentile_ci(samples):
        s = sorted(samples)
        lo = s[int(0.025 * len(s))]
        hi = s[int(0.975 * len(s)) - 1]
        return lo, hi

    macro_lo, macro_hi = percentile_ci(macro_samples)

    per_class_result = {}
    for cls in CLASSES:
        lo, hi = percentile_ci(per_class_samples[cls])
        per_class_result[cls] = {
            "f1": point_per_class[cls]["f1"],
            "support": point_per_class[cls]["support"],
            "ci_low": lo,
            "ci_high": hi,
            "low_support": point_per_class[cls]["support"] < LOW_SUPPORT_THRESHOLD,
        }

    return {
        "accuracy": point_acc,
        "macro_f1": point_macro,
        "macro_ci_low": macro_lo,
        "macro_ci_high": macro_hi,
        "n": n,
        "per_class": per_class_result,
    }


def main():
    data = load_long(IN_PATH)

    all_results = {}
    lines = []
    add = lines.append

    add("=" * 100)
    add("Bootstrap 95% confidence intervals — CIA impact")
    add(f"{N_RESAMPLES} CVE-level resamples, percentile method, seed {SEED}.")
    add("All three classes (NONE/LOW/HIGH) have real support -- single macro-F1 CI per cell")
    add("(no rare-class 'supported subset' split needed, unlike attack_vector).")
    add("=" * 100)
    add("")

    for comp in COMPONENTS:
        add("-" * 100)
        add(comp)
        add("-" * 100)
        add(f"{'Model':<20}{'Condition':<12}{'Accuracy':<10}{'Macro-F1':<10}{'95% CI':<20}")
        comp_results = {}
        for model in MODELS:
            for condition in CONDITIONS:
                key = (model, condition)
                pairs = data[comp][key]
                res = bootstrap_cell(pairs)
                comp_results[f"{model}|{condition}"] = res
                add(
                    f"{model:<20}{condition:<12}{res['accuracy']:<10.3f}"
                    f"{res['macro_f1']:<10.3f}[{res['macro_ci_low']:.3f}, {res['macro_ci_high']:.3f}]"
                )
        add("")
        add("  Per-class F1 with 95% CI:")
        add(f"  {'Model':<20}{'Condition':<12}{'Class':<8}{'n':<6}{'F1':<8}{'95% CI'}")
        for model in MODELS:
            for condition in CONDITIONS:
                res = comp_results[f"{model}|{condition}"]
                for cls in CLASSES:
                    d = res["per_class"][cls]
                    flag = "  [LOW SUPPORT]" if d["low_support"] else ""
                    add(
                        f"  {model:<20}{condition:<12}{cls:<8}{d['support']:<6}"
                        f"{d['f1']:<8.3f}[{d['ci_low']:.3f}, {d['ci_high']:.3f}]{flag}"
                    )
        add("")
        all_results[comp] = comp_results

    report = "\n".join(lines)
    print(report)

    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write(report)
    with open(RESULTS_PATH, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2)

    print(f"\nWritten to {REPORT_PATH} and {RESULTS_PATH}")


if __name__ == "__main__":
    main()