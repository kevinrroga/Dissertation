"""
McNemar significance testing - attack vector.

Run from cve-ner-dissertation/scoring_for_attack_vector/
    python mcnemar_attack_vector.py

Reads : ../ultimate_dataset/merging_results.json
Writes: mcnemar_attack_vector_report.txt
        mcnemar_attack_vector_results.json

Requires: statsmodels   (pip install statsmodels)

What it does
------------
McNemar compares two systems on the SAME CVEs. It looks only at CVEs where the
two disagree: of those, is the split lopsided beyond chance? A CVE counts as
"correct" if the extracted value maps to the ground truth (declines and wrong
answers both count as not-correct - the same definition used for F1).

Comparisons (tied to the research questions):
  - zero_shot vs few_shot, within each model      (does prompting help?)
  - model vs model, within each condition          (which model is better?)

Nine tests total. Raw p-values are Holm-Bonferroni corrected.

Robustness: each comparison uses only the CVEs present in BOTH cells. On a
clean file that is all 500; if a cell is missing CVEs, the script reports how
many were dropped instead of crashing.
"""

import json
import os
from itertools import combinations

from statsmodels.stats.contingency_tables import mcnemar

ENTITY = "attack_vector"
CLASSES = {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}
INPUT = os.path.join("..", "ultimate_dataset", "merging_results.json")
ALPHA = 0.05
MIN_EXACT = 25          # below this many disagreements, use the exact test


def correct(record):
    """1 if the extracted value maps to the ground truth class, else 0."""
    gt = record.get("ground_truth", {}).get(ENTITY)
    block = record.get("extracted")
    raw = block.get(ENTITY) if isinstance(block, dict) else None
    if not isinstance(raw, str):
        return 0
    label = "_".join(raw.strip().strip(".,;:").lower().split()).replace("-", "_").upper()
    return int(label in CLASSES and label == gt)


def load_cells(path):
    """Return {(model, condition): {cve_id: 0/1}}."""
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    cells = {}
    for r in rows:
        key = (r["model"], r["prompt_condition"])
        cells.setdefault(key, {})[r["cve_id"]] = correct(r)
    return cells


def compare(name_a, a, name_b, b):
    """Run one McNemar test on two {cve: 0/1} dicts."""
    shared = sorted(set(a) & set(b))
    dropped = (len(a) - len(shared)) + (len(b) - len(shared))

    a_only = sum(1 for c in shared if a[c] and not b[c])   # A right, B wrong
    b_only = sum(1 for c in shared if b[c] and not a[c])   # B right, A wrong
    both = sum(1 for c in shared if a[c] and b[c])
    neither = len(shared) - both - a_only - b_only
    discordant = a_only + b_only

    exact = discordant < MIN_EXACT
    result = mcnemar([[both, a_only], [b_only, neither]],
                     exact=exact, correction=not exact)

    winner = name_a if a_only > b_only else name_b if b_only > a_only else "tie"

    return {
        "a": name_a, "b": name_b,
        "n_compared": len(shared), "dropped": dropped,
        "a_better": a_only, "b_better": b_only, "discordant": discordant,
        "test": "exact" if exact else "chi-square",
        "p_raw": float(result.pvalue), "favours": winner,
    }


def holm(tests):
    """Add Holm-Bonferroni corrected p-values and significance flags."""
    m = len(tests)
    running = 0.0
    for rank, t in enumerate(sorted(tests, key=lambda x: x["p_raw"])):
        running = max(running, min((m - rank) * t["p_raw"], 1.0))
        t["p_holm"] = running
        t["significant"] = running < ALPHA
    return tests


def build_tests(cells):
    models = sorted({m for m, _ in cells})
    conditions = sorted({c for _, c in cells})
    tests = []

    # prompting: zero vs few-shot, per model
    for m in models:
        (c1, c2) = conditions
        tests.append(compare(f"{m} [{c1}]", cells[(m, c1)],
                             f"{m} [{c2}]", cells[(m, c2)]))

    # models: pairwise, per condition
    for cond in conditions:
        for m1, m2 in combinations(models, 2):
            tests.append(compare(f"{m1} [{cond}]", cells[(m1, cond)],
                                 f"{m2} [{cond}]", cells[(m2, cond)]))
    return tests


def write_report(tests, path):
    lines = []
    def out(s=""):
        print(s)
        lines.append(s)

    out(f"McNemar significance testing - {ENTITY}")
    out(f"{len(tests)} comparisons, Holm-Bonferroni corrected, alpha = {ALPHA}")
    out("A CVE is 'correct' if extracted maps to ground truth; declines count as wrong.")
    out("'b' = A right/B wrong, 'c' = B right/A wrong. Only disagreements inform the test.")
    out("")

    any_dropped = any(t["dropped"] for t in tests)
    if any_dropped:
        out("WARNING: some comparisons dropped CVEs not present in both cells.")
        out("On a clean 500-CVE file this should never happen - check your input.")
        out("")

    head = (f"{'A':30}{'B':30}{'b':>4}{'c':>4}{'disc':>6}"
            f"{'n':>5}{'p_raw':>9}{'p_holm':>9}  sig")
    out(head)
    out("-" * len(head))
    for t in sorted(tests, key=lambda x: x["p_raw"]):
        out(f"{t['a']:30}{t['b']:30}"
            f"{t['a_better']:4}{t['b_better']:4}{t['discordant']:6}"
            f"{t['n_compared']:5}{t['p_raw']:9.4f}{t['p_holm']:9.4f}  "
            f"{'yes' if t['significant'] else 'no'}")

    out("")
    out("Significant row: the two systems differ beyond chance; b vs c gives")
    out("direction and size. Non-significant prompting rows mean worked examples")
    out("made no reliable difference - itself a finding.")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    if not os.path.exists(INPUT):
        raise SystemExit(f"Not found: {INPUT}\nRun from scoring_for_attack_vector/.")

    cells = load_cells(INPUT)
    tests = holm(build_tests(cells))
    write_report(tests, "mcnemar_attack_vector_report.txt")

    with open("mcnemar_attack_vector_results.json", "w") as f:
        json.dump({"entity": ENTITY, "alpha": ALPHA,
                   "correction": "holm-bonferroni", "tests": tests}, f, indent=2)

    print("\nWritten: mcnemar_attack_vector_report.txt")
    print("Written: mcnemar_attack_vector_results.json")


if __name__ == "__main__":
    main()