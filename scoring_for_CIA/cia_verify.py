"""
CIA impact: data verification and harvest.

Run from cve-ner-dissertation/scoring_for_CIA/
    python cia_verify.py

Reads : ../ultimate_dataset/merging_results.json
Writes: cia_verify_report.txt   (human-readable)
        cia_verify_summary.json (machine-readable, for later reuse)

Direct port of verify_attack_vector.py. Same five checks, same purpose, run
once per CIA component (confidentiality_impact, integrity_impact,
availability_impact) instead of once for the single attack_vector entity.

  1. Verify structural integrity of the merged results.
  2. Verify ground truth consistency and label set, per component.
  3. Report ground truth class distribution over unique CVEs, per component.
  4. Harvest the distinct extracted values, per component (input to the
     normalisation map - confirms the closed-label-set finding already made
     ad hoc in chat, now as a saved, reproducible check).
  5. Break down nulls (declines) by model and condition, per component.

This script only inspects. It scores nothing and changes nothing.
"""

import json
import os
import sys
from collections import Counter, defaultdict

COMPONENTS = ["confidentiality_impact", "integrity_impact", "availability_impact"]

DEFAULT_INPUT = os.path.join("..", "ultimate_dataset", "merging_results.json")
REPORT_TXT = "cia_verify_report.txt"
REPORT_JSON = "cia_verify_summary.json"

EXPECTED_GT_LABELS = {"NONE", "LOW", "HIGH"}


class Report:
    """Collects lines so the same output goes to screen and to file."""

    def __init__(self):
        self.lines = []

    def __call__(self, text=""):
        print(text)
        self.lines.append(text)

    def rule(self, title):
        self("")
        self(title)
        self("-" * len(title))

    def save(self, path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(self.lines) + "\n")


def load(path):
    if not os.path.exists(path):
        raise SystemExit(
            f"Input file not found: {path}\n"
            "Run this script from scoring_for_CIA/, or pass the path:\n"
            "    python cia_verify.py /full/path/to/merging_results.json"
        )
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    if not isinstance(rows, list):
        raise SystemExit("Expected a JSON list of result records.")
    return rows


def check_structure(rows, out, summary):
    """Same structural check as attack_vector's - runs once, not per component,
    since it's about the file shape, not any one entity."""
    out.rule("1. Structure")

    models = Counter(r["model"] for r in rows)
    conditions = Counter(r["prompt_condition"] for r in rows)
    valid = Counter(r.get("valid") for r in rows)

    out(f"total rows: {len(rows)}")
    out(f"models: {dict(models)}")
    out(f"conditions: {dict(conditions)}")
    out(f"valid flag: {dict(valid)}")

    per_cve = Counter(r["cve_id"] for r in rows)
    out(f"unique CVEs: {len(per_cve)}")
    out(f"rows per CVE: {dict(Counter(per_cve.values()))}")

    expected = len(models) * len(conditions)
    odd = {c: n for c, n in per_cve.items() if n != expected}
    out(f"CVEs not appearing exactly {expected} times: {len(odd)}")
    for cve, n in list(odd.items())[:10]:
        out(f"   {cve}: {n}")

    summary["structure"] = {
        "total_rows": len(rows),
        "models": dict(models),
        "conditions": dict(conditions),
        "valid_flag": {str(k): v for k, v in valid.items()},
        "unique_cves": len(per_cve),
        "expected_rows_per_cve": expected,
        "cves_with_wrong_row_count": len(odd),
    }


def check_ground_truth(rows, component, out, summary):
    out.rule(f"2. Ground truth consistency — {component}")

    gt_by_cve = defaultdict(set)
    for r in rows:
        gt_by_cve[r["cve_id"]].add(r["ground_truth"].get(component))

    inconsistent = {c: v for c, v in gt_by_cve.items() if len(v) > 1}
    out(f"CVEs with inconsistent ground truth: {len(inconsistent)}")
    for cve, vals in list(inconsistent.items())[:10]:
        out(f"   {cve}: {sorted(map(str, vals))}")

    labels = {next(iter(v)) for v in gt_by_cve.values()}
    unexpected = sorted(str(l) for l in labels if l not in EXPECTED_GT_LABELS)
    missing = sum(1 for v in gt_by_cve.values() if next(iter(v)) is None)

    out(f"observed label set: {sorted(map(str, labels))}")
    out(f"unexpected labels: {unexpected or 'none'}")
    out(f"CVEs with null ground truth: {missing}")

    summary["ground_truth"] = {
        "inconsistent_cves": len(inconsistent),
        "observed_labels": sorted(map(str, labels)),
        "unexpected_labels": unexpected,
        "null_ground_truth_cves": missing,
    }
    return gt_by_cve


def report_distribution(gt_by_cve, component, out, summary):
    out.rule(f"3. Ground truth distribution (unique CVEs) — {component}")

    dist = Counter(next(iter(v)) for v in gt_by_cve.values())
    total = sum(dist.values())

    out(f"{'class':10} {'n':>5} {'%':>7}")
    for label, n in dist.most_common():
        out(f"{str(label):10} {n:5} {100 * n / total:6.1f}%")
    out(f"{'TOTAL':10} {total:5}")

    thin = [l for l, n in dist.items() if n < 20]
    if thin:
        out("")
        out("NOTE: classes with n < 20 — per-class F1 will be unstable.")
        for label in thin:
            out(f"   {label} (n={dist[label]})")
    else:
        out("")
        out("All classes have n >= 20 - no low-support classes for this component")
        out("(unlike attack_vector's ADJACENT_NETWORK/PHYSICAL).")

    summary["distribution"] = {
        "counts": {str(k): v for k, v in dist.items()},
        "total": total,
        "low_support_classes": {str(l): dist[l] for l in thin},
    }


def harvest_extracted(rows, component, out, summary):
    out.rule(f"4. Extracted values (normalisation map input) — {component}")

    values = Counter(r["extracted"].get(component) for r in rows)
    out(f"distinct values: {len(values)}")
    out(f"{'n':>5}  value")
    for value, n in values.most_common():
        out(f"{n:5}  {value!r}")

    summary["extracted_values"] = {str(k): v for k, v in values.items()}


def breakdown_nulls(rows, component, out, summary):
    out.rule(f"5. Null extractions (declines) by model and condition — {component}")

    models = sorted(set(r["model"] for r in rows))
    conditions = sorted(set(r["prompt_condition"] for r in rows))

    out(f"{'model':22}" + "".join(f"{c:>14}" for c in conditions) + f"{'total':>10}")

    table = {}
    grand = 0
    for model in models:
        line = f"{model:22}"
        row_total = 0
        table[model] = {}
        for condition in conditions:
            subset = [
                r for r in rows
                if r["model"] == model and r["prompt_condition"] == condition
            ]
            nulls = sum(1 for r in subset if r["extracted"].get(component) is None)
            pct = 100 * nulls / len(subset) if subset else 0.0
            table[model][condition] = {"nulls": nulls, "n": len(subset), "pct": round(pct, 2)}
            row_total += nulls
            line += f"{f'{nulls} ({pct:.1f}%)':>14}"
        grand += row_total
        out(line + f"{row_total:>10}")

    out(f"{'TOTAL':22}" + " " * (14 * len(conditions)) + f"{grand:>10}")

    null_and_valid = sum(
        1 for r in rows
        if r["extracted"].get(component) is None and r.get("valid") is True
    )
    out("")
    out(f"nulls in rows flagged valid=True: {null_and_valid}")
    out("(these are extraction refusals/declines, not malformed responses)")

    summary["nulls"] = {"by_model_condition": table, "total": grand,
                        "null_but_valid": null_and_valid}


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT
    rows = load(path)

    out = Report()
    summary = {"input_file": os.path.abspath(path), "components": COMPONENTS,
               "per_component": {}}

    out(f"CIA impact verification — {path}")

    # Structural check runs once (file-level, not entity-level).
    check_structure(rows, out, summary)

    for component in COMPONENTS:
        comp_summary = {}
        gt_by_cve = check_ground_truth(rows, component, out, comp_summary)
        report_distribution(gt_by_cve, component, out, comp_summary)
        harvest_extracted(rows, component, out, comp_summary)
        breakdown_nulls(rows, component, out, comp_summary)
        summary["per_component"][component] = comp_summary

    out("")
    out("Done. Record the per-component distributions and null counts in the decision log.")

    out.save(REPORT_TXT)
    with open(REPORT_JSON, "w") as f:
        json.dump(summary, f, indent=2)

    print()
    print(f"Written: {REPORT_TXT}")
    print(f"Written: {REPORT_JSON}")


if __name__ == "__main__":
    main()