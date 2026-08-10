"""
McNemar significance testing — vulnerability type.

Run from cve-ner-dissertation/scoring_for_vulnerability_type/
    python mcnemar_vulnerability_type.py

Reads : vulnerability_type_pillar_scored_details.json
Writes: mcnemar_vulnerability_type_report.txt
        mcnemar_vulnerability_type_results.json

Requires: statsmodels   (pip install statsmodels --break-system-packages)

What it does
------------
McNemar compares two systems evaluated on the SAME 500 CVEs. It looks only at
CVEs where the two systems disagree (discordant pairs): of those, is the split
significantly lopsided toward one system, or consistent with chance?

Correctness definition (mirrors score_pillar.py exactly):
    A record is correct if layer_1_result == "correct", meaning the model's
    predicted label resolved to a CWE listed in the ground truth. Abstentions
    (null predictions) and wrong CWEs both count as incorrect. This is the
    strict accuracy definition used in the headline summary table, so the
    significance test and the point estimate use the same definition of success.

    NOTE: vulnerability type uses strict accuracy, not per-class F1. Unlike
    attack vector (4 classes) and CIA (3 classes), vulnerability type has 145
    possible CWEs in this dataset — per-class F1 would be statistically
    meaningless at that granularity. One binary correct/incorrect outcome per
    record is the appropriate unit of analysis.

Comparisons (tied to the research questions):
    - zero_shot vs few_shot, within each model       (RQ2: does prompting help?)
    - model vs model, within each condition           (RQ2/RQ3: which model?)
    That is 3 prompting + 6 model-pair = 9 tests total.
    Identical structure to attack_vector McNemar.

Multiple comparisons:
    Holm-Bonferroni corrected across all 9 tests, alpha = 0.05.
    Same correction scope as attack_vector (one entity, one family).

Test variant:
    Exact binomial when discordant count < MIN_EXACT (25), otherwise
    chi-square with continuity correction (statsmodels). Same threshold
    as attack_vector.

Effect size:
    b = A correct & B wrong, c = B correct & A wrong. Reported alongside p
    so the direction and magnitude of any difference is visible without having
    to infer it from the accuracy table.
"""

import json
import os
from itertools import combinations

from statsmodels.stats.contingency_tables import mcnemar

INPUT = "vulnerability_type_pillar_scored_details.json"
REPORT_PATH = "mcnemar_vulnerability_type_report.txt"
RESULTS_PATH = "mcnemar_vulnerability_type_results.json"

MODELS = ["claude-sonnet-4.6", "deepseek-v4-pro", "gpt-5.5"]
CONDITIONS = ["zero_shot", "few_shot"]
ALPHA = 0.05
MIN_EXACT = 25


def load_cells(path):
    """
    Return {(model, condition): {cve_id: bool}} where True = correct.
    Reads layer_1_result directly from the scored details file — no
    re-normalisation needed, the scorer has already applied the strict rule.
    """
    with open(path, encoding="utf-8") as f:
        records = json.load(f)

    cells = {}
    for r in records:
        key = (r["model"], r["prompt_condition"])
        cells.setdefault(key, {})[r["cve_id"]] = (r["layer_1_result"] == "correct")
    return cells


def run_mcnemar(name_a, cell_a, name_b, cell_b):
    """
    Run one McNemar test comparing two {cve_id: bool} dicts.
    Only CVEs present in both cells are included (should always be all 500
    on a clean file; dropped count is reported as a diagnostic if not).
    """
    shared = sorted(set(cell_a) & set(cell_b))
    dropped = (len(cell_a) - len(shared)) + (len(cell_b) - len(shared))

    # b = A correct, B wrong  |  c = B correct, A wrong
    b = sum(1 for cve in shared if cell_a[cve] and not cell_b[cve])
    c = sum(1 for cve in shared if cell_b[cve] and not cell_a[cve])
    both_correct = sum(1 for cve in shared if cell_a[cve] and cell_b[cve])
    both_wrong   = sum(1 for cve in shared if not cell_a[cve] and not cell_b[cve])

    discordant = b + c
    table = [[both_correct, b], [c, both_wrong]]

    if discordant == 0:
        return {
            "a": name_a, "b_name": name_b,
            "n_compared": len(shared), "dropped": dropped,
            "b": b, "c": c, "discordant": discordant,
            "test": "no_discordant_pairs",
            "p_raw": 1.0, "favours": "tie",
        }

    exact = discordant < MIN_EXACT
    result = mcnemar(table, exact=exact, correction=not exact)
    favours = name_a if b > c else name_b if c > b else "tie"

    return {
        "a": name_a, "b_name": name_b,
        "n_compared": len(shared), "dropped": dropped,
        "b": b, "c": c, "discordant": discordant,
        "test": "exact_binomial" if exact else "chi_square_corrected",
        "p_raw": float(result.pvalue), "favours": favours,
    }


def holm_bonferroni(tests):
    """Add p_holm and significant fields in place. Returns same list."""
    m = len(tests)
    running = 0.0
    for rank, t in enumerate(sorted(tests, key=lambda x: x["p_raw"])):
        running = max(running, min((m - rank) * t["p_raw"], 1.0))
        t["p_holm"] = running
        t["significant"] = running < ALPHA
    return tests


def build_tests(cells):
    tests = []

    # prompting: zero_shot vs few_shot, within each model
    for model in MODELS:
        tests.append(run_mcnemar(
            f"{model} [zero_shot]", cells[(model, "zero_shot")],
            f"{model} [few_shot]",  cells[(model, "few_shot")],
        ))

    # models: pairwise, within each condition
    for condition in CONDITIONS:
        for m1, m2 in combinations(MODELS, 2):
            tests.append(run_mcnemar(
                f"{m1} [{condition}]", cells[(m1, condition)],
                f"{m2} [{condition}]", cells[(m2, condition)],
            ))

    return tests


def write_report(tests, path):
    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    out("McNemar significance testing — vulnerability type")
    out(f"{len(tests)} comparisons, Holm-Bonferroni corrected, alpha = {ALPHA}")
    out("Correctness: layer_1_result == 'correct' (strict accuracy, same as summary table).")
    out("'b' = A right/B wrong, 'c' = B right/A wrong. Only discordant pairs inform the test.")
    out("Abstentions and wrong CWEs both count as incorrect.")
    out("")

    any_dropped = any(t["dropped"] for t in tests)
    if any_dropped:
        out("WARNING: some comparisons dropped CVEs not present in both cells.")
        out("On a clean 500-CVE file this should not happen — check your input.")
        out("")

    header = (f"{'A':36}{'B':36}{'b':>4}{'c':>4}{'disc':>6}"
              f"{'n':>5}{'p_raw':>9}{'p_holm':>9}  sig")
    out(header)
    out("-" * len(header))

    for t in sorted(tests, key=lambda x: x["p_raw"]):
        out(f"{t['a']:36}{t['b_name']:36}"
            f"{t['b']:4}{t['c']:4}{t['discordant']:6}"
            f"{t['n_compared']:5}{t['p_raw']:9.4f}{t['p_holm']:9.4f}  "
            f"{'yes ***' if t['significant'] else 'no'}")

    out("")
    out("Interpretation:")
    out("  significant row  — the two systems differ beyond chance; b vs c gives")
    out("                     direction (which was better) and size (by how much).")
    out("  non-significant prompting row — few-shot examples made no reliable")
    out("                     difference for that model — itself a finding.")
    out("  non-significant model row     — the two models are statistically")
    out("                     indistinguishable on this entity despite any")
    out("                     difference in raw accuracy.")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    if not os.path.exists(INPUT):
        raise SystemExit(
            f"Not found: {INPUT}\n"
            f"Run from the directory containing vulnerability_type_pillar_scored_details.json"
        )

    cells = load_cells(INPUT)
    tests = holm_bonferroni(build_tests(cells))
    write_report(tests, REPORT_PATH)

    with open(RESULTS_PATH, "w") as f:
        json.dump({
            "entity": "vulnerability_type",
            "alpha": ALPHA,
            "correction": "holm-bonferroni",
            "n_tests": len(tests),
            "correctness_definition": "layer_1_result == correct (strict accuracy)",
            "tests": tests,
        }, f, indent=2)

    print(f"\nWritten: {REPORT_PATH}")
    print(f"Written: {RESULTS_PATH}")


if __name__ == "__main__":
    main()