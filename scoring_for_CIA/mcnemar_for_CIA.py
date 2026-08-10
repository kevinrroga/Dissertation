"""
McNemar significance testing — CIA impact.

Run from cve-ner-dissertation/scoring_for_CIA/
    python mcnemar_cia.py

Reads : outputs/cia_long.csv   (from cia_scorer.py)
Writes: mcnemar_cia_report.txt
        mcnemar_cia_results.json

Requires: statsmodels   (pip install statsmodels --break-system-packages)

This mirrors the attack_vector McNemar design exactly. Differences are noted
explicitly below rather than left implicit.

What this tests
----------------
McNemar's test compares two systems evaluated on the SAME 500 CVEs. It looks
only at the CVEs where the two systems disagree (discordant pairs): of those,
is the split significantly lopsided toward one system, or consistent with
chance? Concordant cases (both right / both wrong) carry no information and
are excluded by construction.

Decision 1 — per-item correctness:
    Uses the 'correct' column already computed in cia_long.csv, which applies
    the STRICT null policy locked in cia_scorer.py (abstention = incorrect).
    Same principle as attack_vector: the significance test uses the identical
    definition of success as the headline F1 table, so the two don't disagree
    about what "correct" means.

Decision 2 — comparisons tested, PER COMPONENT (tied to the research questions):
    - zero_shot vs few_shot, within each model         (RQ2: does prompting help)
    - model vs model, within each condition             (RQ2/RQ3: which model)
    That's 3 + 6 = 9 tests per component (same count as attack_vector had for
    the whole entity). CIA has three components (confidentiality, integrity,
    availability), scored independently per this study's central design
    choice — so this runs 9 tests x 3 components = 27 tests total.

Decision 3 — multiple comparisons, CORRECTED PER COMPONENT:
    Holm-Bonferroni is applied separately within each component's 9 tests,
    not across all 27 at once. Rationale: confidentiality, integrity and
    availability are treated as three independent classification tasks
    throughout this study (never pooled into one CIA score), so each gets
    its own family-wise error control, exactly as attack_vector — a single
    entity — got one correction across its own 9 tests. If you want a single
    correction across all 27 instead, that's a one-line change (concatenate
    the p-value lists before calling holm_bonferroni) — flagged here as a
    deliberate choice, not an oversight.

Test variant:
    Exact binomial when the discordant count is small (< MIN_EXACT), otherwise
    the chi-square approximation with continuity correction (statsmodels).

Effect size:
    Reported alongside p, not instead of it: b = row-model-correct/
    col-model-wrong, c = col-model-correct/row-model-wrong. "31 of 40
    disagreements favoured Claude" is more informative than "p=0.002" alone.
"""

import csv
import json
import itertools
from collections import defaultdict

from statsmodels.stats.contingency_tables import mcnemar

IN_PATH = "outputs/cia_long.csv"
REPORT_PATH = "mcnemar_cia_report.txt"
RESULTS_PATH = "mcnemar_cia_results.json"

COMPONENTS = ["confidentiality_impact", "integrity_impact", "availability_impact"]
MODELS = ["claude-sonnet-4.6", "deepseek-v4-pro", "gpt-5.5"]
CONDITIONS = ["zero_shot", "few_shot"]

MIN_EXACT = 25  # below this many discordant pairs, use exact binomial, not chi-square
ALPHA = 0.05


def load_long(path):
    """cve_id -> component -> (model, condition) -> correct (bool)"""
    data = defaultdict(lambda: defaultdict(dict))
    n_rows = 0
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cve = row["cve_id"]
            comp = row["component"]
            key = (row["model"], row["condition"])
            data[comp][cve][key] = row["correct"].strip().lower() == "true"
            n_rows += 1
    return data, n_rows


def paired_correctness(comp_data, key_a, key_b):
    """
    Returns (a_list, b_list, n, dropped) for two (model,condition) cells,
    aligned on the CVEs both cells have. 'dropped' flags data gaps rather
    than silently truncating -- same diagnostic attack_vector's version has.
    """
    a_list, b_list = [], []
    dropped = 0
    for cve, cells in comp_data.items():
        if key_a in cells and key_b in cells:
            a_list.append(cells[key_a])
            b_list.append(cells[key_b])
        else:
            dropped += 1
    return a_list, b_list, len(a_list), dropped


def run_mcnemar(a_list, b_list):
    """
    a_list/b_list: paired booleans (same CVE order).
    Returns dict with b, c (discordant counts), p-value, method used.
    Convention: b = A correct & B wrong, c = B correct & A wrong.
    """
    b = sum(1 for a, bb in zip(a_list, b_list) if a and not bb)
    c = sum(1 for a, bb in zip(a_list, b_list) if bb and not a)

    both_correct = sum(1 for a, bb in zip(a_list, b_list) if a and bb)
    both_wrong = sum(1 for a, bb in zip(a_list, b_list) if not a and not bb)

    table = [[both_correct, b], [c, both_wrong]]
    n_discordant = b + c

    if n_discordant == 0:
        return {"b": b, "c": c, "n_discordant": 0, "p_value": 1.0, "method": "no_discordant_pairs"}

    exact = n_discordant < MIN_EXACT
    result = mcnemar(table, exact=exact, correction=not exact)
    return {
        "b": b,
        "c": c,
        "n_discordant": n_discordant,
        "p_value": float(result.pvalue),
        "method": "exact_binomial" if exact else "chi_square_corrected",
    }


def holm_bonferroni(results, alpha=ALPHA):
    """
    results: list of dicts each containing 'p_value'. Adds 'p_adj' and
    'significant' (bool) in place, using the Holm step-down procedure.
    """
    order = sorted(range(len(results)), key=lambda i: results[i]["p_value"])
    m = len(results)
    running_max = 0.0
    for rank, idx in enumerate(order):
        p = results[idx]["p_value"]
        adj = min(1.0, p * (m - rank))
        running_max = max(running_max, adj)  # enforce monotonicity
        results[idx]["p_adj"] = running_max
        results[idx]["significant"] = running_max < alpha
    return results


def build_comparisons(comp_data, comp_name):
    """Builds the 9 comparisons for one component: 3 prompting + 6 model-pair."""
    tests = []

    # zero_shot vs few_shot, within each model
    for model in MODELS:
        key_a = (model, "zero_shot")
        key_b = (model, "few_shot")
        a, b, n, dropped = paired_correctness(comp_data, key_a, key_b)
        res = run_mcnemar(a, b)
        res.update({
            "component": comp_name,
            "comparison_type": "prompting",
            "label": f"{model}: zero_shot vs few_shot",
            "n": n,
            "dropped": dropped,
        })
        tests.append(res)

    # model vs model, within each condition
    for condition in CONDITIONS:
        for m1, m2 in itertools.combinations(MODELS, 2):
            key_a = (m1, condition)
            key_b = (m2, condition)
            a, b, n, dropped = paired_correctness(comp_data, key_a, key_b)
            res = run_mcnemar(a, b)
            res.update({
                "component": comp_name,
                "comparison_type": "model",
                "label": f"{condition}: {m1} vs {m2}",
                "n": n,
                "dropped": dropped,
            })
            tests.append(res)

    return tests


def main():
    data, n_rows = load_long(IN_PATH)

    all_results = {}
    lines = []
    add = lines.append

    add("=" * 90)
    add("McNemar significance testing — CIA impact")
    add("=" * 90)
    add("A CVE is 'correct' if extracted maps to ground truth (strict null policy: abstention = wrong).")
    add("'b' = A right/B wrong, 'c' = B right/A wrong. Only disagreements inform the test.")
    add("9 comparisons per component, Holm-Bonferroni corrected WITHIN each component, alpha = 0.05.")
    add("")

    for comp in COMPONENTS:
        comp_data = data[comp]
        tests = build_comparisons(comp_data, comp)
        tests = holm_bonferroni(tests)
        all_results[comp] = tests

        add("-" * 90)
        add(comp)
        add("-" * 90)
        for t in tests:
            flag = "  ***" if t["significant"] else ""
            warn = f"  [WARNING: {t['dropped']} CVEs dropped, data gap]" if t["dropped"] else ""
            add(
                f"  {t['label']:<45} n={t['n']:<4} b={t['b']:<4} c={t['c']:<4} "
                f"p={t['p_value']:.4f}  p_adj={t['p_adj']:.4f}  ({t['method']}){flag}{warn}"
            )
        add("")

    report = "\n".join(lines)
    print(report)

    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write(report)
    with open(RESULTS_PATH, "w", encoding="utf-8") as fh:
        json.dump(all_results, fh, indent=2)

    print(f"\nWritten to {REPORT_PATH} and {RESULTS_PATH}")


if __name__ == "__main__":
    main()