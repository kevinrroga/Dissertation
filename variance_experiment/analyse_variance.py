"""
Variance analysis for the stability experiment.

Run from cve-ner-dissertation/:
    python variance_experiment/analyse_variance.py

Or from variance_experiment/:
    python analyse_variance.py

Reads:
    variance_experiment/results/variance_log.jsonl   (experiment log)
    ultimate_dataset/dataset_v1_locked_24jun_with_cwe_names.json  (ground truth)

Writes:
    variance_experiment/results/variance_summary.json
    variance_experiment/results/variance_report.txt

Metrics computed per cell (CVE × model × condition), then aggregated:

  Stability (no ground truth needed):
    inter_rep_agreement_rate
        Fraction of (CVE, model, condition) groups where all 5 reps returned
        exactly the same `parsed` dict.  A group with fewer than REPS valid
        reps is counted as "not fully agreed" (conservative).

    per_field_agreement_rate
        For each of the 6 fields: fraction of groups where all valid reps
        returned the same value for that field.

  Accuracy (against NVD ground truth):
    For attack_vector and the three CIA fields (confidentiality, integrity,
    availability) a correct/incorrect verdict is computed per rep using the
    same case-insensitive normalisation as the main scoring scripts.

    For vulnerability_type a simple normalised string match is used (lower-
    case, collapse whitespace, strip punctuation).  This is a conservative
    proxy — the dissertation's CWE alias scorer is more permissive — so the
    accuracy figures here will be slightly lower than the main results.
    Use these numbers only for within-experiment variance comparison.

    per_rep_accuracy (per field, per cell):
        List of 5 booleans (or None if rep was invalid).

    mean_accuracy (per field, across CVEs for each model/condition pair):
        Weighted mean over CVEs (invalid reps contribute None, excluded from
        denominator).

    std_accuracy:
        Standard deviation of per-CVE accuracy (average across 5 reps) for
        each model/condition pair.

    bootstrap_ci_95 (per field, per model/condition):
        5,000 CVE-level bootstrap resamples, percentile method, seed=42.

  Agreement on verdict (requires ground truth):
    verdict_full_agreement_rate
        For each (CVE, model, condition) group: among the REPS reps that are
        valid, do they ALL give the same correct/incorrect verdict for every
        scored field?  Reported as the fraction of groups that satisfy this.

    verdict_per_field_agreement_rate
        Same, but per field.

Requires: nothing beyond the standard library.
"""

import json
import os
import random
import re
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LOG_PATH = HERE / "results" / "variance_log.jsonl"
GT_PATH = ROOT / "ultimate_dataset" / "dataset_v1_locked_24jun_with_cwe_names.json"
OUT_JSON = HERE / "results" / "variance_summary.json"
OUT_TXT = HERE / "results" / "variance_report.txt"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPS = 5
N_BOOT = 5000
SEED = 42

SCORED_FIELDS = [
    "vulnerability_type",
    "attack_vector",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]

AV_MAP = {
    "network": "NETWORK",
    "adjacent network": "ADJACENT_NETWORK",
    "adjacent": "ADJACENT_NETWORK",
    "local": "LOCAL",
    "physical": "PHYSICAL",
}

CIA_MAP = {
    "none": "NONE",
    "low": "LOW",
    "high": "HIGH",
}


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def norm_av(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    return AV_MAP.get(s)


def norm_cia(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    return CIA_MAP.get(s)


def norm_vuln_type(value) -> str | None:
    """Simple normalisation for vulnerability_type.

    Lowercase, collapse whitespace, strip leading/trailing punctuation.
    This is a conservative proxy for the CWE alias matcher; accuracy figures
    will be slightly lower than the main dissertation scorer.
    """
    if value is None:
        return None
    s = str(value).strip().lower()
    s = re.sub(r"[^a-z0-9 _/-]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s if s else None


def norm_gt_av(value) -> str | None:
    """Ground truth AV is stored as e.g. 'ADJACENT_NETWORK'."""
    if value is None:
        return None
    return str(value).strip().upper()


def norm_gt_cia(value) -> str | None:
    if value is None:
        return None
    return str(value).strip().upper()


def norm_gt_vuln(cwe_names: list) -> str | None:
    """Return a normalised set of ground-truth vulnerability labels.

    The GT stores a list of CWE names (e.g. ['Buffer Overflow']).
    We normalise each name with norm_vuln_type and return the set.
    """
    if not cwe_names:
        return None
    normalised = [norm_vuln_type(n) for n in cwe_names if n]
    normalised = [n for n in normalised if n]
    return set(normalised) if normalised else None


def score_field(field: str, pred_parsed: dict | None, gt: dict) -> bool | None:
    """Return True (correct), False (incorrect), or None (invalid/missing)."""
    if pred_parsed is None:
        return None

    if field == "attack_vector":
        pred = norm_av(pred_parsed.get("attack_vector"))
        truth = norm_gt_av(gt.get("attack_vector"))
        if pred is None or truth is None:
            return None
        return pred == truth

    if field in ("confidentiality_impact", "integrity_impact", "availability_impact"):
        pred = norm_cia(pred_parsed.get(field))
        truth = norm_gt_cia(gt.get(field))
        if pred is None or truth is None:
            return None
        return pred == truth

    if field == "vulnerability_type":
        pred = norm_vuln_type(pred_parsed.get("vulnerability_type"))
        gt_names = gt.get("cwe_names", [])
        truth_set = norm_gt_vuln(gt_names)
        if pred is None or not truth_set:
            return None
        return pred in truth_set

    return None  # unscored field (affected_component)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_log() -> list[dict]:
    if not LOG_PATH.exists():
        raise SystemExit(
            f"Log not found: {LOG_PATH.resolve()}\n"
            "Run run_variance.py first."
        )
    records = []
    bad_lines = 0
    with LOG_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                bad_lines += 1
    if bad_lines:
        print(f"Warning: skipped {bad_lines} malformed line(s) in the log.")
    return records


def load_ground_truth() -> dict[str, dict]:
    """Return {cve_id: cve_record} from the locked dataset."""
    if not GT_PATH.exists():
        raise SystemExit(f"Ground truth not found: {GT_PATH.resolve()}")
    with GT_PATH.open("r", encoding="utf-8") as f:
        rows = json.load(f)
    return {r["cve_id"]: r for r in rows}


# ---------------------------------------------------------------------------
# Group log records into cells
# ---------------------------------------------------------------------------

def group_records(records: list[dict]) -> dict:
    """Return {(cve_id, model, condition): {rep: record}}."""
    cells = defaultdict(dict)
    for rec in records:
        key = (rec.get("cve_id"), rec.get("model"), rec.get("prompt_condition"))
        rep = rec.get("rep")
        if None in key or rep is None:
            continue
        cells[key][rep] = rec
    return cells


# ---------------------------------------------------------------------------
# Stability metrics (no ground truth)
# ---------------------------------------------------------------------------

def compute_stability(cells: dict) -> dict:
    """Return per-(model, condition) stability metrics."""
    # Aggregate by (model, condition)
    mc_groups = defaultdict(list)  # (model, condition) -> list of groups
    for (cve_id, model, condition), reps in cells.items():
        mc_groups[(model, condition)].append(reps)

    results = {}
    for (model, condition), groups in sorted(mc_groups.items()):
        n_groups = len(groups)

        # Full JSON agreement (all valid reps identical)
        full_agree = 0
        for reps in groups:
            valid_parsed = [
                json.dumps(reps[r]["parsed"], sort_keys=True)
                for r in sorted(reps)
                if reps[r].get("valid") and reps[r].get("parsed") is not None
            ]
            if len(valid_parsed) == REPS and len(set(valid_parsed)) == 1:
                full_agree += 1

        # Per-field agreement
        field_agree = defaultdict(int)
        field_eligible = defaultdict(int)
        for reps in groups:
            for field in SCORED_FIELDS + ["affected_component"]:
                values = [
                    reps[r]["parsed"].get(field)
                    for r in sorted(reps)
                    if reps[r].get("valid") and reps[r].get("parsed") is not None
                ]
                if len(values) == REPS:
                    field_eligible[field] += 1
                    if len(set(str(v) for v in values)) == 1:
                        field_agree[field] += 1

        results[(model, condition)] = {
            "n_groups": n_groups,
            "full_agreement_rate": full_agree / n_groups if n_groups else None,
            "full_agreement_count": full_agree,
            "per_field_agreement": {
                f: {
                    "rate": field_agree[f] / field_eligible[f] if field_eligible[f] else None,
                    "count": field_agree[f],
                    "eligible": field_eligible[f],
                }
                for f in SCORED_FIELDS + ["affected_component"]
            },
        }
    return results


# ---------------------------------------------------------------------------
# Accuracy metrics (with ground truth)
# ---------------------------------------------------------------------------

def compute_accuracy(cells: dict, ground_truth: dict) -> dict:
    """Return per-(model, condition) accuracy metrics for each scored field."""
    mc_by_field = defaultdict(lambda: defaultdict(list))
    # mc_by_field[(model, condition)][field] = list of per-CVE mean accuracy
    # (mean over the 5 reps, None if no valid reps)

    for (cve_id, model, condition), reps in cells.items():
        gt = ground_truth.get(cve_id)
        if gt is None:
            continue
        for field in SCORED_FIELDS:
            verdicts = []
            for r in sorted(reps):
                rec = reps[r]
                if rec.get("valid"):
                    v = score_field(field, rec.get("parsed"), gt)
                    if v is not None:
                        verdicts.append(v)
            if verdicts:
                mc_by_field[(model, condition)][field].append(
                    sum(verdicts) / len(verdicts)
                )

    results = {}
    rng = random.Random(SEED)
    for (model, condition), field_data in sorted(mc_by_field.items()):
        results[(model, condition)] = {}
        for field, per_cve_means in field_data.items():
            n = len(per_cve_means)
            if n == 0:
                results[(model, condition)][field] = {
                    "n_cves": 0,
                    "mean": None,
                    "std": None,
                    "ci_low_95": None,
                    "ci_high_95": None,
                }
                continue

            mean = sum(per_cve_means) / n
            variance = sum((x - mean) ** 2 for x in per_cve_means) / n
            std = variance ** 0.5

            # Bootstrap CI
            boot_means = []
            for _ in range(N_BOOT):
                sample = [rng.choice(per_cve_means) for _ in range(n)]
                boot_means.append(sum(sample) / n)
            boot_means.sort()
            ci_lo = boot_means[int(0.025 * N_BOOT)]
            ci_hi = boot_means[int(0.975 * N_BOOT)]

            results[(model, condition)][field] = {
                "n_cves": n,
                "mean": round(mean, 4),
                "std": round(std, 4),
                "ci_low_95": round(ci_lo, 4),
                "ci_high_95": round(ci_hi, 4),
            }
    return results


# ---------------------------------------------------------------------------
# Verdict agreement (correct/incorrect agreement across reps)
# ---------------------------------------------------------------------------

def compute_verdict_agreement(cells: dict, ground_truth: dict) -> dict:
    """For each (model, condition), fraction of (CVE, field) pairs where all
    valid reps gave the same correct/incorrect verdict."""
    mc_agree = defaultdict(lambda: defaultdict(lambda: {"agree": 0, "total": 0}))

    for (cve_id, model, condition), reps in cells.items():
        gt = ground_truth.get(cve_id)
        if gt is None:
            continue
        for field in SCORED_FIELDS:
            verdicts = []
            for r in sorted(reps):
                rec = reps[r]
                if rec.get("valid"):
                    v = score_field(field, rec.get("parsed"), gt)
                    if v is not None:
                        verdicts.append(v)
            if not verdicts:
                continue
            mc_agree[(model, condition)][field]["total"] += 1
            if len(set(verdicts)) == 1:  # all same verdict
                mc_agree[(model, condition)][field]["agree"] += 1

    results = {}
    for (model, condition), field_data in sorted(mc_agree.items()):
        results[(model, condition)] = {}
        for field, counts in field_data.items():
            total = counts["total"]
            agree = counts["agree"]
            results[(model, condition)][field] = {
                "verdict_agreement_rate": round(agree / total, 4) if total else None,
                "agree_count": agree,
                "total_count": total,
            }
    return results


# ---------------------------------------------------------------------------
# Coverage summary (how many cells are complete)
# ---------------------------------------------------------------------------

def compute_coverage(records: list[dict]) -> dict:
    """Count valid / invalid / missing reps per (model, condition)."""
    counter = defaultdict(lambda: {"valid": 0, "invalid": 0})
    for rec in records:
        key = (rec.get("model"), rec.get("prompt_condition"))
        if rec.get("valid"):
            counter[key]["valid"] += 1
        else:
            counter[key]["invalid"] += 1
    return {f"{m}|{c}": v for (m, c), v in sorted(counter.items())}


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def write_report(stability, accuracy, verdict_agreement, coverage, path: Path):
    lines = []

    def out(s=""):
        lines.append(s)

    out("Variance / stability experiment — analysis report")
    out(f"Bootstrap: {N_BOOT} resamples, CVE-level, percentile method, seed={SEED}")
    out(f"Scoring note: vulnerability_type uses simple normalised string match,")
    out(f"  not the full CWE alias scorer — accuracy will be conservative.")
    out("")

    # Coverage
    out("=== COVERAGE (valid calls) ===")
    out(f"{'cell':38}{'valid':>8}{'invalid':>10}")
    out("-" * 56)
    for cell_key, counts in coverage.items():
        out(f"{cell_key:38}{counts['valid']:8}{counts['invalid']:10}")
    out("")

    # Stability
    out("=== STABILITY (inter-rep agreement, no ground truth) ===")
    out("Full-JSON agreement = all 5 valid reps produced identical parsed output.")
    out("")
    out(f"{'cell':38}{'full_agree_rate':>17}{'n_groups':>10}")
    out("-" * 65)
    for (model, condition), s in stability.items():
        label = f"{model}|{condition}"
        rate = s["full_agreement_rate"]
        rate_str = f"{rate:.4f}" if rate is not None else "   n/a"
        out(f"{label:38}{rate_str:>17}{s['n_groups']:>10}")
    out("")

    out("Per-field agreement rates (fraction of groups where all valid reps agree):")
    out("")
    all_fields = SCORED_FIELDS + ["affected_component"]
    header = f"{'cell':38}" + "".join(f"{f[:14]:>16}" for f in all_fields)
    out(header)
    out("-" * (38 + 16 * len(all_fields)))
    for (model, condition), s in stability.items():
        label = f"{model}|{condition}"
        row = f"{label:38}"
        for f in all_fields:
            fd = s["per_field_agreement"].get(f, {})
            rate = fd.get("rate")
            row += f"{'n/a':>16}" if rate is None else f"{rate:>16.4f}"
        out(row)
    out("")

    # Accuracy
    out("=== ACCURACY (mean per-CVE accuracy against NVD ground truth, 95% CI) ===")
    out("")
    for field in SCORED_FIELDS:
        out(f"  Field: {field}")
        out(f"  {'cell':38}{'mean':>8}{'std':>8}{'CI_low':>10}{'CI_high':>10}{'n_cves':>8}")
        out("  " + "-" * 82)
        for (model, condition), field_data in accuracy.items():
            label = f"{model}|{condition}"
            m = field_data.get(field)
            if m is None:
                out(f"  {label:38}{'n/a':>8}{'n/a':>8}{'n/a':>10}{'n/a':>10}{'n/a':>8}")
                continue
            mean = m["mean"]
            std = m["std"]
            ci_lo = m["ci_low_95"]
            ci_hi = m["ci_high_95"]
            n = m["n_cves"]
            if mean is None:
                out(f"  {label:38}{'n/a':>8}{'n/a':>8}{'n/a':>10}{'n/a':>10}{n:>8}")
            else:
                out(f"  {label:38}{mean:>8.4f}{std:>8.4f}{ci_lo:>10.4f}{ci_hi:>10.4f}{n:>8}")
        out("")

    # Verdict agreement
    out("=== VERDICT AGREEMENT (fraction of groups where all reps agree correct/incorrect) ===")
    out("")
    for field in SCORED_FIELDS:
        out(f"  Field: {field}")
        out(f"  {'cell':38}{'agree_rate':>12}{'agree':>8}{'total':>8}")
        out("  " + "-" * 66)
        for (model, condition), field_data in verdict_agreement.items():
            label = f"{model}|{condition}"
            fd = field_data.get(field)
            if fd is None:
                out(f"  {label:38}{'n/a':>12}{'n/a':>8}{'n/a':>8}")
                continue
            rate = fd["verdict_agreement_rate"]
            rate_str = f"{rate:.4f}" if rate is not None else "   n/a"
            out(f"  {label:38}{rate_str:>12}{fd['agree_count']:>8}{fd['total_count']:>8}")
        out("")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    for line in lines:
        print(line)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print(f"Loading log: {LOG_PATH.resolve()}")
    records = load_log()
    print(f"  {len(records)} records loaded.")

    print(f"Loading ground truth: {GT_PATH.resolve()}")
    ground_truth = load_ground_truth()
    print(f"  {len(ground_truth)} CVEs in ground truth.")

    cells = group_records(records)
    print(f"  {len(cells)} unique (CVE, model, condition) groups.\n")

    coverage = compute_coverage(records)

    print("Computing stability metrics...")
    stability = compute_stability(cells)

    print("Computing accuracy metrics (bootstrap may take a few seconds)...")
    accuracy = compute_accuracy(cells, ground_truth)

    print("Computing verdict agreement...")
    verdict_agreement = compute_verdict_agreement(cells, ground_truth)

    # Serialise
    summary = {
        "n_bootstrap": N_BOOT,
        "seed": SEED,
        "reps": REPS,
        "coverage": coverage,
        "stability": {
            f"{m}|{c}": v for (m, c), v in stability.items()
        },
        "accuracy": {
            f"{m}|{c}": v for (m, c), v in accuracy.items()
        },
        "verdict_agreement": {
            f"{m}|{c}": v for (m, c), v in verdict_agreement.items()
        },
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with OUT_JSON.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\nWritten: {OUT_JSON.resolve()}")
    write_report(stability, accuracy, verdict_agreement, coverage, OUT_TXT)
    print(f"\nWritten: {OUT_TXT.resolve()}")


if __name__ == "__main__":
    main()
