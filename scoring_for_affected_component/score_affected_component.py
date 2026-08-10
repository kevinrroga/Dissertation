"""
Affected Component Scorer
=========================
Scores LLM-extracted affected_component values against CPE-derived ground truth
strings from the NVD dataset.

Place this script in:   cve-ner-dissertation/scoring_for_affected_component/
Input is read from:     cve-ner-dissertation/ultimate_dataset/merging_results.json
Outputs are written to: cve-ner-dissertation/scoring_for_affected_component/outputs/

    cd cve-ner-dissertation/scoring_for_affected_component
    python score_affected_component.py

Requires: nothing beyond the standard library.


METHODOLOGY DECISIONS
---------------------
1. NATURE OF THE TASK
   Unlike attack_vector and CIA, affected_component has no closed class set.
   Ground truth is a list of one or more CPE-derived product name strings
   (e.g. ["acer predator connect w6x firmware"]), and the LLM returns free
   prose (e.g. "Wi-Fi device blocking feature"). Standard per-class
   precision/recall/F1 is not applicable. Instead, each record is scored as
   a binary match (matched / not matched), and binary precision, recall and
   F1 are computed treating "match" as the positive class. This is standard
   practice for open-ended entity extraction in the NER literature.

2. MATCHING LOGIC — TWO LAYERS
   Layer 1 — Token overlap (primary):
     Both the extracted string and each ground truth string are normalised
     (lowercased, punctuation stripped, hyphens/underscores replaced with
     spaces, split into tokens, stopwords removed). A match is recorded if
     the meaningful token set of any ground truth component is a subset of
     the tokens found in the extracted string, OR if the extracted tokens
     are a subset of the ground truth tokens. This is deliberately
     bidirectional to handle cases where the LLM extracts a shorter or
     longer form of the correct product name.

   Layer 2 — Vendor fallback (partial match):
     If Layer 1 fails, the vendor token (first word of the ground truth
     string, e.g. "acer") is checked for presence in the extracted string.
     A vendor-only hit is recorded as a PARTIAL outcome. This is scored as
     not-matched for the headline metric but reported separately, because it
     represents genuine partial knowledge (the model identified the right
     vendor but not the specific product). This distinction is informative
     for the Discussion chapter.

3. MULTI-COMPONENT GROUND TRUTH
   18 of 500 CVEs have multiple affected components (e.g. many firmware
   variants from the same vendor). A record is matched if the extraction
   matches ANY one component in the ground truth list (any-match policy).
   This is consistent with how multi-CWE ground truth is handled in the
   vulnerability type scorer.

4. FIVE OUTCOME CATEGORIES (parallel to other scorers)
   Match    extraction passes Layer 1 token overlap against any GT component
   Partial  extraction fails Layer 1 but vendor token is found (Layer 2)
   No Match extraction present and non-null, but fails both layers
   Declined extraction is JSON null (model gave no answer)
   Malformed extracted block missing or not a dict

   For the headline binary metric:
     Match    -> TP
     Partial  -> FN  (reported separately but not counted as correct)
     No Match -> FN
     Declined -> FN
     Malformed -> FN
   No FP is recorded for Partial / No Match / Declined / Malformed,
   consistent with the treatment of Unmapped/Declined/Malformed in the
   attack_vector and CIA scorers.

5. HEADLINE METRIC
   Binary F1, precision and recall treating "match" as the positive class.
   Accuracy (match / total) is reported alongside. The partial match rate
   is reported as a secondary diagnostic, not a primary metric.

6. RECORDS RETAINED IN THE DENOMINATOR
   All 500 CVEs are retained per cell, never excluded. Consistent with
   the other scorers.

7. NORMALISATION
   Lowercase, strip punctuation, replace hyphens/underscores with spaces,
   split on whitespace. Stopwords removed: a small fixed set of words
   that carry no product-discriminating information ("firmware", "software",
   "the", "a", "an", "for", "and", "of", "in", "on", "with", "plugin",
   "extension", "library", "package"). The stopword list is intentionally
   conservative — only terms that would trivially cause false matches.

8. KNOWN LIMITATION
   The ground truth is CPE-derived product names (the product as registered
   in the NVD), while LLMs naturally extract sub-component or feature names
   from the description text (e.g. "MQTT broker" instead of "acer predator
   connect w6x firmware"). A No Match result does not purely indicate model
   failure — it may reflect a genuine difference in what "affected component"
   means at the product level vs. the code level. This limitation is
   discussed in the dissertation's Discussion chapter.

OUTPUTS
-------
  outputs/affected_component_scores.csv     headline metrics per model x condition
  outputs/affected_component_outcomes.csv   outcome breakdown per cell
  outputs/affected_component_long.csv       one row per CVE x model x condition
  outputs/affected_component_summary.txt    human-readable report
"""

import csv
import json
import os
import re
from collections import Counter, defaultdict

RESULTS_PATH = os.path.join("..", "ultimate_dataset", "merging_results.json")
OUT_DIR = "outputs"

ENTITY = "affected_component"

OUTCOMES = ["Match", "Partial", "No Match", "Declined", "Malformed"]

STOPWORDS = {
    "firmware", "software", "the", "a", "an", "for", "and", "of",
    "in", "on", "with", "plugin", "extension", "library", "package",
    "application", "app", "tool", "service", "system", "platform",
    "module", "component", "api",
}


def normalise_tokens(text):
    if not isinstance(text, str) or not text.strip():
        return frozenset()
    s = text.lower()
    s = re.sub(r"[-_/]", " ", s)
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    tokens = s.split()
    tokens = [t for t in tokens if t not in STOPWORDS and len(t) > 1]
    return frozenset(tokens)


def vendor_token(gt_string):
    s = gt_string.lower()
    s = re.sub(r"[-_/]", " ", s)
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    ordered = [t for t in s.split() if t not in STOPWORDS and len(t) > 1]
    return ordered[0] if ordered else None


def layer1_match(extracted_tokens, gt_tokens):
    if not gt_tokens or not extracted_tokens:
        return False
    overlap = gt_tokens & extracted_tokens
    if not overlap:
        return False
    return gt_tokens <= extracted_tokens or extracted_tokens <= gt_tokens


def layer2_match(extracted_text, gt_string):
    vendor = vendor_token(gt_string)
    if not vendor:
        return False
    extracted_normalised = re.sub(r"[-_/]", " ", extracted_text.lower())
    extracted_normalised = re.sub(r"[^a-z0-9\s]", " ", extracted_normalised)
    return vendor in extracted_normalised.split()


def match_against_gt_list(extracted_text, gt_list):
    extracted_tokens = normalise_tokens(extracted_text)
    for gt in gt_list:
        gt_tokens = normalise_tokens(gt)
        if layer1_match(extracted_tokens, gt_tokens):
            return "Match"
    for gt in gt_list:
        if layer2_match(extracted_text, gt):
            return "Partial"
    return "No Match"


def classify(record):
    gt_list = (record.get("ground_truth") or {}).get(ENTITY) or []
    extracted_block = record.get("extracted")
    if not isinstance(extracted_block, dict) or ENTITY not in extracted_block:
        return "Malformed", None, gt_list
    raw = extracted_block.get(ENTITY)
    if raw is None:
        return "Declined", None, gt_list
    if not isinstance(raw, str) or not raw.strip():
        return "Declined", None, gt_list
    outcome = match_against_gt_list(raw, gt_list)
    return outcome, raw, gt_list


def score_cell(records):
    outcome_counts = Counter()
    long_rows = []
    for record in records:
        outcome, extracted, gt_list = classify(record)
        outcome_counts[outcome] += 1
        long_rows.append({
            "cve_id": record.get("cve_id"),
            "outcome": outcome,
            "extracted": extracted,
            "ground_truth": gt_list,
            "matched": outcome == "Match",
        })
    total = len(records)
    n_match = outcome_counts["Match"]
    tp = n_match
    fn = total - n_match
    fp = 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = n_match / total if total > 0 else 0.0
    partial = outcome_counts["Partial"]
    no_match = outcome_counts["No Match"]
    declined = outcome_counts["Declined"]
    malformed = outcome_counts["Malformed"]
    return {
        "n": total,
        "outcomes": {o: outcome_counts[o] for o in OUTCOMES},
        "tp": tp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": accuracy,
        "partial_count": partial,
        "partial_rate": partial / total if total > 0 else 0.0,
        "no_match_count": no_match,
        "no_prediction_count": declined + malformed,
        "no_prediction_rate": (declined + malformed) / total if total > 0 else 0.0,
        "not_matched_total": partial + no_match + declined + malformed,
    }, long_rows


def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def write_scores_csv(cells, path):
    rows = []
    for (model, condition), r in sorted(cells.items()):
        rows.append([model, condition,
            round(r["f1"], 4), round(r["precision"], 4),
            round(r["recall"], 4), round(r["accuracy"], 4),
            r["n"], r["tp"], r["fn"],
            r["partial_count"], r["no_match_count"], r["no_prediction_count"]])
    write_csv(path, ["model", "condition", "f1", "precision", "recall",
                     "accuracy", "n", "tp", "fn", "partial",
                     "no_match", "no_prediction"], rows)


def write_outcomes_csv(cells, path):
    rows = []
    for (model, condition), r in sorted(cells.items()):
        o = r["outcomes"]
        rows.append([model, condition] + [o.get(cat, 0) for cat in OUTCOMES])
    write_csv(path, ["model", "condition"] + OUTCOMES, rows)


def write_long_csv(all_long_rows, path):
    rows = [[r["cve_id"], r["model"], r["condition"], r["outcome"],
             r["matched"], r["extracted"] or "", "; ".join(r["ground_truth"])]
            for r in all_long_rows]
    write_csv(path, ["cve_id", "model", "condition", "outcome",
                     "matched", "extracted", "ground_truth"], rows)


def build_report(cells, n_records):
    lines = []
    add = lines.append
    add("=" * 90)
    add("AFFECTED COMPONENT SCORING")
    add("=" * 90)
    add(f"Records: {n_records}   Cells: {len(cells)} (3 models x 2 conditions)")
    add("")
    add("Matching policy:")
    add("  Layer 1 (Match)   — bidirectional token-overlap against any GT component")
    add("  Layer 2 (Partial) — vendor-token presence fallback")
    add("  Any-match across multi-component GT lists.")
    add("  Partial is FN for the headline metric; reported separately for discussion.")
    add("")
    add("-" * 90)
    add("1. OUTCOME BREAKDOWN per cell")
    add("-" * 90)
    add(f"{'model':<25}{'condition':<14}" + "".join(f"{o:<12}" for o in OUTCOMES))
    for (model, condition), r in sorted(cells.items()):
        o = r["outcomes"]
        add(f"{model:<25}{condition:<14}" +
            "".join(f"{o.get(cat, 0):<12}" for cat in OUTCOMES))
    add("")
    add("-" * 90)
    add("2. BINARY F1  [PRIMARY METRIC]")
    add("-" * 90)
    add(f"{'model':<25}{'condition':<14}{'F1':<9}{'precision':<11}"
        f"{'recall':<9}{'accuracy':<10}{'partial%':<10}")
    for (model, condition), r in sorted(cells.items()):
        add(f"{model:<25}{condition:<14}"
            f"{r['f1']:<9.3f}{r['precision']:<11.3f}"
            f"{r['recall']:<9.3f}{r['accuracy']:<10.3f}"
            f"{100 * r['partial_rate']:<10.1f}")
    add("")
    add("-" * 90)
    add("3. COUNTS")
    add("-" * 90)
    add(f"{'model':<25}{'condition':<14}{'n':<6}{'TP':<6}{'FN':<6}"
        f"{'partial':<9}{'no_match':<11}{'no_pred':<9}")
    for (model, condition), r in sorted(cells.items()):
        add(f"{model:<25}{condition:<14}"
            f"{r['n']:<6}{r['tp']:<6}{r['fn']:<6}"
            f"{r['partial_count']:<9}{r['no_match_count']:<11}"
            f"{r['no_prediction_count']:<9}")
    add("")
    add("NOTE: FP is defined as 0 throughout. Precision is always 1.0.")
    add("The meaningful metric is recall (= accuracy). F1 reported for comparability.")
    add("")
    add("NOTE: No Match does not purely indicate failure — LLMs extract feature-level")
    add("names from description text rather than CPE-registered product names.")
    return "\n".join(lines)


def load_records(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Could not find: {os.path.abspath(path)}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    records = load_records(RESULTS_PATH)
    by_cell = defaultdict(list)
    for r in records:
        by_cell[(r.get("model"), r.get("prompt_condition"))].append(r)
    cells = {}
    all_long_rows = []
    for (model, condition), cell_records in sorted(by_cell.items()):
        result, long_rows = score_cell(cell_records)
        cells[(model, condition)] = result
        for row in long_rows:
            row["model"] = model
            row["condition"] = condition
        all_long_rows.extend(long_rows)
    write_scores_csv(cells, os.path.join(OUT_DIR, "affected_component_scores.csv"))
    write_outcomes_csv(cells, os.path.join(OUT_DIR, "affected_component_outcomes.csv"))
    write_long_csv(all_long_rows, os.path.join(OUT_DIR, "affected_component_long.csv"))
    report = build_report(cells, len(records))
    with open(os.path.join(OUT_DIR, "affected_component_summary.txt"), "w",
              encoding="utf-8") as fh:
        fh.write(report)
    print(report)
    print(f"\nWritten to {os.path.abspath(OUT_DIR)}/")


if __name__ == "__main__":
    main()