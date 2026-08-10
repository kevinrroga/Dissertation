"""
build_cwe_inventory.py

Purpose
-------
Build the vulnerability-type evaluation resources from merging_results.json:

1. cwe_inventory.csv
2. cwe_aliases_draft.json
3. predicted_vulnerability_labels.csv
4. unresolved_vulnerability_labels.csv

This script does NOT calculate the final model scores. It prepares and audits
the vocabulary needed before the alias dictionary is reviewed and frozen.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent

# Change this path only if merging_results.json is stored elsewhere.
INPUT_FILE = ROOT / "merging_results.json"

OUTPUT_DIR = ROOT / "vulnerability_type_evaluation"

CWE_INVENTORY_FILE = OUTPUT_DIR / "cwe_inventory.csv"
ALIASES_DRAFT_FILE = OUTPUT_DIR / "cwe_aliases_draft.json"
PREDICTED_LABELS_FILE = OUTPUT_DIR / "predicted_vulnerability_labels.csv"
UNRESOLVED_FILE = OUTPUT_DIR / "unresolved_vulnerability_labels.csv"


# A deliberately small list of unambiguous, widely recognised aliases.
# Add only aliases that refer to one CWE without depending on context.
MANUAL_ALIASES: dict[str, set[str]] = {
    "CWE-79": {
        "xss",
        "cross site scripting",
    },
    "CWE-611": {
        "xxe",
        "xml external entity",
        "xml external entity injection",
    },
    "CWE-918": {
        "ssrf",
        "server side request forgery",
    },
    "CWE-416": {
        "uaf",
        "use after free",
    },
    "CWE-367": {
        "toctou",
        "time of check time of use",
    },
}


# ---------------------------------------------------------------------------
# NORMALISATION
# ---------------------------------------------------------------------------

def normalize_label(value: Any) -> str:
    """
    Normalise only superficial linguistic variation.

    This function deliberately avoids semantic similarity and fuzzy matching.
    """
    if value is None:
        return ""

    text = str(value).strip().lower()

    # Standardise apostrophes and separators.
    text = text.replace("’", "'")
    text = text.replace("–", "-")
    text = text.replace("—", "-")
    text = text.replace("&", " and ")

    # Treat punctuation and hyphens as spaces.
    text = re.sub(r"[-_/]", " ", text)
    text = re.sub(r"[\"'`(),.:;{}\[\]]", " ", text)

    # Remove duplicated whitespace.
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def extract_parenthetical_aliases(name: str) -> set[str]:
    """
    Extract useful short names found inside parentheses.

    Example:
      Improper Neutralization ... ('Cross-site Scripting')
      -> cross site scripting
    """
    aliases: set[str] = set()

    for content in re.findall(r"\(([^()]*)\)", name or ""):
        candidate = normalize_label(content)
        if candidate:
            aliases.add(candidate)

    return aliases


def derive_short_aliases(official_name: str) -> set[str]:
    """
    Generate conservative aliases from an official name.

    Only parenthetical short names are generated automatically. The script
    does not guess semantic synonyms.
    """
    aliases = {normalize_label(official_name)}
    aliases.update(extract_parenthetical_aliases(official_name))
    aliases.discard("")
    return aliases


# ---------------------------------------------------------------------------
# INPUT VALIDATION
# ---------------------------------------------------------------------------

def load_results(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise SystemExit(
            f"Input file not found:\n  {path.resolve()}\n\n"
            "Place build_cwe_inventory.py beside merging_results.json, or edit "
            "INPUT_FILE at the top of the script."
        )

    try:
        with path.open("r", encoding="utf-8") as handle:
            rows = json.load(handle)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(rows, list) or not rows:
        raise SystemExit("The input must contain a non-empty JSON list.")

    required_top_level = {
        "cve_id",
        "model",
        "prompt_condition",
        "extracted",
        "ground_truth",
    }

    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise SystemExit(f"Row {index} is not a JSON object.")

        missing = required_top_level - row.keys()
        if missing:
            raise SystemExit(f"Row {index} is missing fields: {sorted(missing)}")

    return rows


# ---------------------------------------------------------------------------
# GROUND-TRUTH EXTRACTION
# ---------------------------------------------------------------------------

def pair_cwes_and_names(
    cwe_ids: list[str],
    names: list[str],
) -> tuple[list[tuple[str, str]], bool]:
    """
    Pair CWE IDs with names when the two lists align.

    Returns:
      pairs
      ambiguous_alignment

    If one CVE contains multiple CWEs and the name list length does not match,
    the names cannot be assigned safely to individual CWE IDs. Those cases are
    flagged rather than guessed.
    """
    clean_ids = [str(item).strip().upper() for item in cwe_ids if item]
    clean_names = [str(item).strip() for item in names if item]

    if len(clean_ids) == len(clean_names):
        return list(zip(clean_ids, clean_names)), False

    if len(clean_ids) == 1 and clean_names:
        # Multiple names may occur because of source inconsistency. Associate
        # all names with the one CWE, while flagging the inconsistency later.
        return [(clean_ids[0], name) for name in clean_names], False

    # Unsafe to assign names to individual CWE IDs.
    return [(cwe_id, "") for cwe_id in clean_ids], True


def build_ground_truth_inventory(
    rows: list[dict[str, Any]],
) -> tuple[
    dict[str, set[str]],
    dict[str, set[str]],
    Counter[str],
    Counter[str],
    set[str],
]:
    """
    Return:
      cwe_to_names
      cwe_to_cves
      cwe_row_counts
      cwe_cve_counts
      ambiguous_cves
    """
    cwe_to_names: dict[str, set[str]] = defaultdict(set)
    cwe_to_cves: dict[str, set[str]] = defaultdict(set)
    cwe_row_counts: Counter[str] = Counter()
    ambiguous_cves: set[str] = set()

    for row in rows:
        cve_id = str(row["cve_id"])
        ground_truth = row.get("ground_truth") or {}

        cwe_ids = ground_truth.get("cwe_ids") or []
        names = ground_truth.get("vulnerability_type") or []

        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]
        if isinstance(names, str):
            names = [names]

        pairs, ambiguous = pair_cwes_and_names(cwe_ids, names)

        if ambiguous:
            ambiguous_cves.add(cve_id)

        seen_in_row: set[str] = set()

        for cwe_id, name in pairs:
            if not cwe_id:
                continue

            if name:
                cwe_to_names[cwe_id].add(name)

            cwe_to_cves[cwe_id].add(cve_id)

            # Count each CWE once per result row.
            if cwe_id not in seen_in_row:
                cwe_row_counts[cwe_id] += 1
                seen_in_row.add(cwe_id)

    cwe_cve_counts = Counter(
        {cwe_id: len(cves) for cwe_id, cves in cwe_to_cves.items()}
    )

    return (
        cwe_to_names,
        cwe_to_cves,
        cwe_row_counts,
        cwe_cve_counts,
        ambiguous_cves,
    )


# ---------------------------------------------------------------------------
# ALIAS DRAFT
# ---------------------------------------------------------------------------

def build_alias_draft(
    cwe_to_names: dict[str, set[str]],
) -> dict[str, dict[str, Any]]:
    draft: dict[str, dict[str, Any]] = {}

    for cwe_id in sorted(cwe_to_names, key=cwe_sort_key):
        official_names = sorted(cwe_to_names[cwe_id])

        aliases: set[str] = set()
        for official_name in official_names:
            aliases.update(derive_short_aliases(official_name))

        aliases.update(
            normalize_label(alias)
            for alias in MANUAL_ALIASES.get(cwe_id, set())
        )
        aliases.discard("")

        draft[cwe_id] = {
            "official_names": official_names,
            "aliases": sorted(aliases),
            "review_status": "draft",
            "notes": "",
        }

    return draft


def build_reverse_alias_index(
    alias_draft: dict[str, dict[str, Any]],
) -> tuple[dict[str, str], dict[str, set[str]]]:
    """
    Build:
      unambiguous_alias_to_cwe
      ambiguous_alias_to_cwes

    An alias mapping to several CWEs is deliberately not accepted.
    """
    candidates: dict[str, set[str]] = defaultdict(set)

    for cwe_id, record in alias_draft.items():
        for alias in record.get("aliases", []):
            normalised = normalize_label(alias)
            if normalised:
                candidates[normalised].add(cwe_id)

    unambiguous: dict[str, str] = {}
    ambiguous: dict[str, set[str]] = {}

    for alias, cwes in candidates.items():
        if len(cwes) == 1:
            unambiguous[alias] = next(iter(cwes))
        else:
            ambiguous[alias] = cwes

    return unambiguous, ambiguous


# ---------------------------------------------------------------------------
# PREDICTED-LABEL INVENTORY
# ---------------------------------------------------------------------------

def build_prediction_inventory(
    rows: list[dict[str, Any]],
    alias_to_cwe: dict[str, str],
    ambiguous_aliases: dict[str, set[str]],
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}

    for row in rows:
        extracted = row.get("extracted") or {}
        raw_prediction = extracted.get("vulnerability_type")
        normalised = normalize_label(raw_prediction)

        key = normalised if normalised else "__ABSENT__"

        ground_truth = row.get("ground_truth") or {}
        gt_cwes = ground_truth.get("cwe_ids") or []
        gt_names = ground_truth.get("vulnerability_type") or []

        if isinstance(gt_cwes, str):
            gt_cwes = [gt_cwes]
        if isinstance(gt_names, str):
            gt_names = [gt_names]

        if key not in grouped:
            grouped[key] = {
                "predicted_label": (
                    str(raw_prediction).strip()
                    if raw_prediction is not None
                    else ""
                ),
                "normalised_label": normalised,
                "frequency": 0,
                "models": set(),
                "prompt_conditions": set(),
                "example_cves": [],
                "ground_truth_cwes": set(),
                "ground_truth_names": set(),
            }

        item = grouped[key]
        item["frequency"] += 1
        item["models"].add(str(row.get("model", "")))
        item["prompt_conditions"].add(str(row.get("prompt_condition", "")))
        item["ground_truth_cwes"].update(str(cwe).upper() for cwe in gt_cwes)
        item["ground_truth_names"].update(str(name) for name in gt_names)

        if len(item["example_cves"]) < 5:
            item["example_cves"].append(str(row["cve_id"]))

    inventory: list[dict[str, Any]] = []

    for item in grouped.values():
        normalised = item["normalised_label"]

        if not normalised:
            automatic_status = "absent"
            candidate_cwe = ""
            ambiguity = ""
        elif normalised in ambiguous_aliases:
            automatic_status = "ambiguous_alias"
            candidate_cwe = ""
            ambiguity = "; ".join(
                sorted(ambiguous_aliases[normalised], key=cwe_sort_key)
            )
        elif normalised in alias_to_cwe:
            automatic_status = "automatic_alias_match"
            candidate_cwe = alias_to_cwe[normalised]
            ambiguity = ""
        else:
            automatic_status = "unresolved"
            candidate_cwe = ""
            ambiguity = ""

        inventory.append(
            {
                "predicted_label": item["predicted_label"],
                "normalised_label": normalised,
                "frequency": item["frequency"],
                "automatic_status": automatic_status,
                "candidate_cwe": candidate_cwe,
                "ambiguous_candidate_cwes": ambiguity,
                "models": "; ".join(sorted(item["models"])),
                "prompt_conditions": "; ".join(
                    sorted(item["prompt_conditions"])
                ),
                "example_cves": "; ".join(item["example_cves"]),
                "observed_ground_truth_cwes": "; ".join(
                    sorted(item["ground_truth_cwes"], key=cwe_sort_key)
                ),
                "observed_ground_truth_names": " | ".join(
                    sorted(item["ground_truth_names"])
                ),
            }
        )

    inventory.sort(
        key=lambda row: (
            row["automatic_status"] != "unresolved",
            -int(row["frequency"]),
            row["normalised_label"],
        )
    )

    return inventory


# ---------------------------------------------------------------------------
# OUTPUT
# ---------------------------------------------------------------------------

def cwe_sort_key(value: str) -> tuple[int, str]:
    match = re.search(r"(\d+)", value or "")
    return (int(match.group(1)) if match else 10**9, value)


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_cwe_inventory(
    path: Path,
    cwe_to_names: dict[str, set[str]],
    cwe_to_cves: dict[str, set[str]],
    cwe_row_counts: Counter[str],
    cwe_cve_counts: Counter[str],
) -> None:
    rows: list[dict[str, Any]] = []

    all_cwes = sorted(
        set(cwe_to_names) | set(cwe_to_cves),
        key=cwe_sort_key,
    )

    for cwe_id in all_cwes:
        names = sorted(cwe_to_names.get(cwe_id, set()))
        rows.append(
            {
                "cwe_id": cwe_id,
                "official_names_observed": " | ".join(names),
                "number_of_observed_names": len(names),
                "unique_cve_count": cwe_cve_counts.get(cwe_id, 0),
                "result_row_count": cwe_row_counts.get(cwe_id, 0),
                "example_cves": "; ".join(
                    sorted(cwe_to_cves.get(cwe_id, set()))[:5]
                ),
                "needs_name_review": "yes" if len(names) != 1 else "no",
            }
        )

    write_csv(
        path,
        [
            "cwe_id",
            "official_names_observed",
            "number_of_observed_names",
            "unique_cve_count",
            "result_row_count",
            "example_cves",
            "needs_name_review",
        ],
        rows,
    )


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    rows = load_results(INPUT_FILE)

    (
        cwe_to_names,
        cwe_to_cves,
        cwe_row_counts,
        cwe_cve_counts,
        ambiguous_cves,
    ) = build_ground_truth_inventory(rows)

    alias_draft = build_alias_draft(cwe_to_names)
    alias_to_cwe, ambiguous_aliases = build_reverse_alias_index(alias_draft)

    prediction_inventory = build_prediction_inventory(
        rows,
        alias_to_cwe,
        ambiguous_aliases,
    )

    unresolved = [
        row
        for row in prediction_inventory
        if row["automatic_status"]
        in {"unresolved", "ambiguous_alias", "absent"}
    ]

    write_cwe_inventory(
        CWE_INVENTORY_FILE,
        cwe_to_names,
        cwe_to_cves,
        cwe_row_counts,
        cwe_cve_counts,
    )

    with ALIASES_DRAFT_FILE.open("w", encoding="utf-8") as handle:
        json.dump(alias_draft, handle, indent=2, ensure_ascii=False)

    prediction_fields = [
        "predicted_label",
        "normalised_label",
        "frequency",
        "automatic_status",
        "candidate_cwe",
        "ambiguous_candidate_cwes",
        "models",
        "prompt_conditions",
        "example_cves",
        "observed_ground_truth_cwes",
        "observed_ground_truth_names",
    ]

    write_csv(PREDICTED_LABELS_FILE, prediction_fields, prediction_inventory)
    write_csv(UNRESOLVED_FILE, prediction_fields, unresolved)

    print("=" * 72)
    print("CWE inventory preparation complete")
    print("=" * 72)
    print(f"Input result rows:             {len(rows)}")
    print(f"Unique ground-truth CWEs:      {len(cwe_to_cves)}")
    print(f"Unique predicted labels:       {len(prediction_inventory)}")
    print(f"Automatically mapped labels:   "
          f"{sum(r['automatic_status'] == 'automatic_alias_match' for r in prediction_inventory)}")
    print(f"Unresolved/ambiguous/absent:   {len(unresolved)}")
    print(f"Ambiguous multi-CWE CVEs:      {len(ambiguous_cves)}")
    print()
    print("Created:")
    print(f"  {CWE_INVENTORY_FILE}")
    print(f"  {ALIASES_DRAFT_FILE}")
    print(f"  {PREDICTED_LABELS_FILE}")
    print(f"  {UNRESOLVED_FILE}")
    print()
    print("Next step:")
    print("  Review unresolved_vulnerability_labels.csv and add only")
    print("  unambiguous aliases to MANUAL_ALIASES or to a frozen JSON file.")


if __name__ == "__main__":
    main()