"""
McNemar significance testing — affected component.

Run from cve-ner-dissertation/scoring_for_affected_component/
    python mcnemar_affected_component.py

Reads : outputs/affected_component_long.csv   (from score_affected_component.py)
Writes: outputs/mcnemar_affected_component_report.txt
        outputs/mcnemar_affected_component_results.json

Requires: statsmodels   (pip install statsmodels --break-system-packages)

WHAT THIS TESTS
---------------
McNemar's test compares two systems evaluated on the SAME 500 CVEs. It looks
only at CVEs where the two systems disagree (discordant pairs): of those, is
the split significantly lopsided toward one system, or consistent with chance?
Concordant cases (both matched / both not-matched) carry no information and
are excluded by construction.

DESIGN DECISIONS (explicit, mirroring mcnemar_for_CIA.py)
----------------------------------------------------------
1. Definition of "correct":
   matched == True in affected_component_long.csv. This is the same binary
   outcome used in the bootstrap and in the headline accuracy metric from the
   scorer. Partial matches count as incorrect, consistent with the scorer's
   FP=0, TP=Match-only policy. The significance test therefore uses the
   identical definition of success as the headline table.

2. Comparisons (9 total, tied to the research questions):
   - zero_shot vs few_shot, within each model (3 tests)     -> RQ2: prompting
   - model vs model, within each condition  (6 tests)       -> RQ2/RQ3: model
   Same structure as attack_vector (9 tests, one entity) and per-component
   CIA (9 tests per component). Consistent across all four entities.

3. Multiple comparisons:
   Holm-Bonferroni applied across all 9 tests. Same procedure and alpha
   (0.05) as attack_vector and CIA.

4. Test variant:
   Exact binomial when discordant pairs < MIN_EXACT (25), otherwise
   chi-square with continuity correction via statsmodels. Same threshold
   and same library call as attack_vector and CIA.

5. Effect size reported:
   b = A correct & B wrong, c = B correct & A wrong. "X of Y disagreements
   favoured model A" is reported alongside p to convey practical magnitude,
   not just statistical significance.

6. Data gaps:
   Comparisons are restricted to CVEs present in both cells. Dropped CVEs
   (if any) are flagged in the output rather than silently excluded.
   On a clean 500-CVE file this count should always be zero.
"""

import csv
import json
import itertools
from collections import defaultdict

from statsmodels.stats.contingency_tables import mcnemar

IN_PATH = "outputs/affected_component_long.csv"
REPORT_PATH = "outputs/mcnemar_affected_component_report.txt"
RESULTS_PATH = "outputs/mcnemar_affected_component_results.json"

MODELS = ["claude-sonnet-4.6", "deepseek-v4-pro", "gpt-5.5"]
CONDITIONS = ["zero_shot", "few_shot"]

MIN_EXACT = 25
ALPHA = 0.05


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_long(path):
    """
    Returns:
      data: {(model, condition): {cve_id: bool}}   True = matched
    """
    data = defaultdict(dict)
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key = (row["model"], row["condition"])
            data[key][row["cve_id"]] = row["matched"].strip().lower() == "true"
    return data


# ---------------------------------------------------------------------------
# McNemar
# ---------------------------------------------------------------------------

def paired_correctness(data, key_a, key_b):
    """
    Align two cells on shared CVEs.
    Returns (a_list, b_list, n_shared, n_dropped).
    """
    shared = sorted(set(data[key_a]) & set(data[key_b]))
    dropped = (len(data[key_a]) - len(shared)) + (len(data[key_b]) - len(shared))
    a_list = [data[key_a][c] for c in shared]
    b_list = [data[key_b][c] for c in shared]
    return a_list, b_list, len(shared), dropped


def run_mcnemar(a_list, b_list):
    """
    a_list / b_list: paired booleans (same CVE order).
    b = A correct & B wrong
    c = B correct & A wrong
    Returns a result dict.
    """
    b = sum(1 for a, bb in zip(a_list, b_list) if a and not bb)
    c = sum(1 for a, bb in zip(a_list, b_list) if bb and not a)
    both_correct = sum(1 for a, bb in zip(a_list, b_list) if a and bb)
    both_wrong   = sum(1 for a, bb in zip(a_list, b_list) if not a and not bb)

    n_discordant = b + c

    if n_discordant == 0:
        return {
            "b": b, "c": c, "n_discordant": 0,
            "p_value": 1.0, "method": "no_discordant_pairs",
        }

    exact = n_discordant < MIN_EXACT
    table = [[both_correct, b], [c, both_wrong]]
    result = mcnemar(table, exact=exact, correction=not exact)

    return {
        "b": b,
        "c": c,
        "n_discordant": n_discordant,
        "p_value": float(result.pvalue),
        "method": "exact_binomial" if exact else "chi_square_corrected",
    }


def holm_bonferroni(tests, alpha=ALPHA):
    """
    Adds p_adj and significant (bool) to each test dict in place.
    Holm step-down procedure.
    """
    order = sorted(range(len(tests)), key=lambda i: tests[i]["p_value"])
    m = len(tests)
    running_max = 0.0
    for rank, idx in enumerate(order):
        adj = min(1.0, tests[idx]["p_value"] * (m - rank))
        running_max = max(running_max, adj)
        tests[idx]["p_adj"] = running_max
        tests[idx]["significant"] = running_max < alpha
    return tests


def build_comparisons(data):
    """9 comparisons: 3 prompting + 6 model-pair."""
    tests = []

    # zero_shot vs few_shot, within each model
    for model in MODELS:
        key_a = (model, "zero_shot")
        key_b = (model, "few_shot")
        a_list, b_list, n, dropped = paired_correctness(data, key_a, key_b)
        res = run_mcnemar(a_list, b_list)
        res.update({
            "label": f"{model}: zero_shot vs few_shot",
            "comparison_type": "prompting",
            "favours": (
                f"{model} [zero_shot]" if res["b"] > res["c"] else
                f"{model} [few_shot]"  if res["c"] > res["b"] else
                "tie"
            ),
            "n": n,
            "dropped": dropped,
        })
        tests.append(res)

    # model vs model, within each condition
    for condition in CONDITIONS:
        for m1, m2 in itertools.combinations(MODELS, 2):
            key_a = (m1, condition)
            key_b = (m2, condition)
            a_list, b_list, n, dropped = paired_correctness(data, key_a, key_b)
            res = run_mcnemar(a_list, b_list)
            res.update({
                "label": f"{condition}: {m1} vs {m2}",
                "comparison_type": "model",
                "favours": (
                    f"{m1} [{condition}]" if res["b"] > res["c"] else
                    f"{m2} [{condition}]" if res["c"] > res["b"] else
                    "tie"
                ),
                "n": n,
                "dropped": dropped,
            })
            tests.append(res)

    return tests


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_report(tests):
    lines = []
    add = lines.append

    add("=" * 90)
    add("McNemar significance testing — affected component")
    add("=" * 90)
    add(f"{len(tests)} comparisons, Holm-Bonferroni corrected, alpha = {ALPHA}.")
    add("A CVE is 'correct' if matched == True (Match outcome only; Partial = incorrect).")
    add("'b' = A correct/B wrong, 'c' = B correct/A wrong. Only discordant pairs inform the test.")
    add("")

    any_dropped = any(t["dropped"] for t in tests)
    if any_dropped:
        add("WARNING: some comparisons dropped CVEs not present in both cells.")
        add("On a clean 500-CVE file this should never happen — check your input.")
        add("")

    add("PROMPTING COMPARISONS (zero_shot vs few_shot, within model)")
    add("-" * 90)
    prompting = [t for t in tests if t["comparison_type"] == "prompting"]
    for t in sorted(prompting, key=lambda x: x["p_value"]):
        flag = "  ***" if t["significant"] else ""
        add(
            f"  {t['label']:<50} n={t['n']:<5} b={t['b']:<4} c={t['c']:<4} "
            f"disc={t['n_discordant']:<4} "
            f"p={t['p_value']:.4f}  p_adj={t['p_adj']:.4f}  ({t['method']}){flag}"
        )
    add("")

    add("MODEL COMPARISONS (pairwise within condition)")
    add("-" * 90)
    model_tests = [t for t in tests if t["comparison_type"] == "model"]
    for t in sorted(model_tests, key=lambda x: x["p_value"]):
        flag = "  ***" if t["significant"] else ""
        add(
            f"  {t['label']:<50} n={t['n']:<5} b={t['b']:<4} c={t['c']:<4} "
            f"disc={t['n_discordant']:<4} "
            f"p={t['p_value']:.4f}  p_adj={t['p_adj']:.4f}  ({t['method']}){flag}"
        )
    add("")

    add("ALL 9 TESTS (sorted by raw p-value)")
    add("-" * 90)
    add(f"  {'label':<50} {'b':>4} {'c':>4} {'disc':>5} {'p_raw':>9} {'p_adj':>9}  sig")
    add("  " + "-" * 86)
    for t in sorted(tests, key=lambda x: x["p_value"]):
        add(
            f"  {t['label']:<50} {t['b']:>4} {t['c']:>4} {t['n_discordant']:>5} "
            f"{t['p_value']:>9.4f} {t['p_adj']:>9.4f}  "
            f"{'yes ***' if t['significant'] else 'no'}"
        )
    add("")
    add("INTERPRETATION")
    add("-" * 90)
    add("Significant prompting row: few-shot reliably differs from zero-shot for")
    add("this model on this entity. Non-significant: worked examples made no")
    add("reliable difference — itself a finding, consistent with the proposal's")
    add("risk analysis acknowledging that prompting gains may not hold.")
    add("")
    add("Significant model row: the two models differ beyond chance on affected")
    add("component extraction. Given the open-ended nature of this entity,")
    add("interpret direction (b vs c) alongside the accuracy gap in the scorer")
    add("output — statistical significance with a small b/c gap has limited")
    add("practical meaning when overall accuracy is ~55%.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    data = load_long(IN_PATH)
    tests = holm_bonferroni(build_comparisons(data))

    report = build_report(tests)
    print(report)

    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write(report)

    with open(RESULTS_PATH, "w", encoding="utf-8") as fh:
        json.dump({
            "entity": "affected_component",
            "alpha": ALPHA,
            "correction": "holm-bonferroni",
            "n_tests": len(tests),
            "correctness_definition": "matched == True (Partial counts as incorrect)",
            "tests": tests,
        }, fh, indent=2)

    print(f"\nWritten: {REPORT_PATH}")
    print(f"Written: {RESULTS_PATH}")


if __name__ == "__main__":
    main()