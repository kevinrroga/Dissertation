"""Standalone layered vulnerability-type scoring script.

Required input files in the same directory:
- merging_results.json
- cwe_aliases_v3_strict_reviewed.json
- cwe_master_vocabulary.json

Outputs:
- vulnerability_type_pillar_scored_details.json
- vulnerability_type_pillar_summary.json
- vulnerability_type_pillar_summary.csv

Layer 1:
- correct
- incorrect

Layer 2, applied only when Layer 1 is incorrect:
- same_pillar_wrong_cwe
- consequence_not_mechanism
- different_pillar
- unmapped_or_absent
"""

from __future__ import annotations

import csv
import json
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent

RESULTS_FILE = BASE_DIR / "merging_results.json"
ALIASES_FILE = BASE_DIR / "cwe_aliases_v3_strict_reviewed.json"
VOCAB_FILE = BASE_DIR / "cwe_master_vocabulary_pillar_grouped.json"

DETAILS_OUTPUT = BASE_DIR / "vulnerability_type_pillar_scored_details.json"
SUMMARY_OUTPUT = BASE_DIR / "vulnerability_type_pillar_summary.json"
CSV_OUTPUT = BASE_DIR / "vulnerability_type_pillar_summary.csv"


SAFE_EQUIVALENT_ALIASES = {
    "integer overflow": "CWE-190",
    "heap buffer overflow": "CWE-122",
    "heap based buffer overflow": "CWE-122",
    "stack buffer overflow": "CWE-121",
    "stack based buffer overflow": "CWE-121",
    "cross site request forgery": "CWE-352",
    "unsafe deserialization": "CWE-502",
    "insecure deserialization": "CWE-502",
    "timing side channel": "CWE-208",
    "template injection": "CWE-1336",
    "toctou race condition": "CWE-367",
    "time of check time of use toctou": "CWE-367",
    "time of check to time of use toctou": "CWE-367",
    "missing authentication": "CWE-306",
    "use after free": "CWE-416",
}


CONSEQUENCE_TERMS = {
    "denial of service",
    "dos",
    "remote code execution",
    "rce",
    "arbitrary code execution",
    "code execution",
    "unauthorized code execution",
    "privilege escalation",
    "local privilege escalation",
    "information disclosure",
    "information exposure",
    "information leak",
    "sensitive data exposure",
    "sensitive information exposure",
    "credential exposure",
    "data exposure",
    "application crash",
    "crash",
    "memory corruption",
    "arbitrary file read",
    "arbitrary file write",
}


EXTRA_BROAD_TERMS = {
    "authentication bypass": {
        "CWE-288", "CWE-289", "CWE-294", "CWE-305", "CWE-306"
    },
    "authorization bypass": {
        "CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-939"
    },
    "security feature bypass": {
        "CWE-288", "CWE-289", "CWE-305", "CWE-693"
    },
    "path traversal": {
        "CWE-22", "CWE-23", "CWE-35", "CWE-36"
    },
    "race condition": {
        "CWE-362", "CWE-364", "CWE-367"
    },
    "resource leak": {
        "CWE-401", "CWE-404", "CWE-772"
    },
    "out of bounds access": {
        "CWE-125", "CWE-126", "CWE-787"
    },
    "out of bounds memory access": {
        "CWE-125", "CWE-126", "CWE-787"
    },
    "out of bounds read write": {
        "CWE-125", "CWE-787"
    },
    "improper input validation": {
        "CWE-20", "CWE-129", "CWE-130", "CWE-1284", "CWE-1287"
    },
    "insufficient input validation": {
        "CWE-20", "CWE-129", "CWE-130", "CWE-1284", "CWE-1287"
    },
    "improper validation": {
        "CWE-20", "CWE-129", "CWE-130", "CWE-1284", "CWE-1287"
    },
    "insufficient validation": {
        "CWE-20", "CWE-129", "CWE-130", "CWE-1284", "CWE-1287"
    },
}


def load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def normalize_label(value: Any) -> str | None:
    if value is None:
        return None

    text = unicodedata.normalize("NFKC", str(value)).lower().strip()
    text = text.replace("&", " and ")
    text = re.sub(r"[-–—]", " ", text)
    text = re.sub(r"[“”‘’'\"`]", "", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    return text or None


def build_alias_resolver(alias_database: dict[str, Any]) -> dict[str, str]:
    alias_to_cwe: dict[str, str] = {}
    duplicate_aliases: dict[str, set[str]] = {}

    for cwe_id, cwe_entry in alias_database["cwes"].items():
        for alias_entry in cwe_entry.get("aliases", []):
            alias = normalize_label(alias_entry.get("alias"))
            if not alias:
                continue

            existing = alias_to_cwe.get(alias)
            if existing is not None and existing != cwe_id:
                duplicate_aliases.setdefault(alias, set()).update(
                    {existing, cwe_id}
                )
            else:
                alias_to_cwe[alias] = cwe_id

    if duplicate_aliases:
        formatted = {
            alias: sorted(cwes)
            for alias, cwes in duplicate_aliases.items()
        }
        raise ValueError(
            f"Duplicate aliases resolving to multiple CWEs: {formatted}"
        )

    alias_to_cwe.update(SAFE_EQUIVALENT_ALIASES)
    return alias_to_cwe


def build_broad_term_map(
    alias_database: dict[str, Any],
) -> dict[str, set[str]]:
    broad_terms: dict[str, set[str]] = {}

    for term, details in alias_database.get("ambiguous_terms", {}).items():
        normalized = normalize_label(term)
        if normalized:
            broad_terms[normalized] = set(details.get("maps_to", []))

    for term, cwes in EXTRA_BROAD_TERMS.items():
        broad_terms[normalize_label(term)] = set(cwes)

    return broad_terms


def resolve_prediction(
    predicted_label: Any,
    alias_to_cwe: dict[str, str],
    known_cwes: set[str],
) -> tuple[str | None, str, str | None]:
    normalized = normalize_label(predicted_label)

    if normalized is None:
        return None, "NULL_OR_EMPTY", None

    direct_match = re.fullmatch(r"(?:cwe\s*)?(\d{1,4})", normalized)
    if direct_match:
        candidate = f"CWE-{int(direct_match.group(1))}"
        if candidate in known_cwes:
            return candidate, "DIRECT_CWE_ID", normalized

    resolved_cwe = alias_to_cwe.get(normalized)
    if resolved_cwe:
        method = (
            "SAFE_EQUIVALENT_ALIAS"
            if normalized in SAFE_EQUIVALENT_ALIASES
            else "STRICT_ALIAS"
        )
        return resolved_cwe, method, normalized

    return None, "UNRESOLVED", normalized


def share_pillar(
    predicted_cwes: set[str],
    ground_truth_cwes: set[str],
    cwe_to_pillar: dict[str, str],
) -> bool:
    predicted_pillars = {
        cwe_to_pillar[cwe]
        for cwe in predicted_cwes
        if cwe in cwe_to_pillar
    }
    ground_truth_pillars = {
        cwe_to_pillar[cwe]
        for cwe in ground_truth_cwes
        if cwe in cwe_to_pillar
    }

    return bool(predicted_pillars & ground_truth_pillars)


def classify_prediction(
    predicted_label: Any,
    ground_truth_cwes: list[str],
    alias_to_cwe: dict[str, str],
    broad_term_map: dict[str, set[str]],
    cwe_to_pillar: dict[str, str],
) -> dict[str, Any]:
    known_cwes = set(cwe_to_pillar)

    resolved_cwe, resolution_method, normalized_label = resolve_prediction(
        predicted_label=predicted_label,
        alias_to_cwe=alias_to_cwe,
        known_cwes=known_cwes,
    )

    ground_truth_set = set(ground_truth_cwes)

    if resolved_cwe in ground_truth_set:
        return {
            "normalized_label": normalized_label,
            "resolved_cwe": resolved_cwe,
            "resolution_method": resolution_method,
            "layer_1_result": "correct",
            "layer_2_error_category": None,
            "explanation": (
                "Prediction resolved to a CWE listed in the ground truth."
            ),
        }

    if normalized_label in CONSEQUENCE_TERMS:
        return {
            "normalized_label": normalized_label,
            "resolved_cwe": resolved_cwe,
            "resolution_method": resolution_method,
            "layer_1_result": "incorrect",
            "layer_2_error_category": "consequence_not_mechanism",
            "explanation": (
                "Prediction names an impact or exploit outcome rather than "
                "the underlying weakness mechanism."
            ),
        }

    if resolved_cwe is not None:
        if share_pillar(
            {resolved_cwe},
            ground_truth_set,
            cwe_to_pillar,
        ):
            error_category = "same_pillar_wrong_cwe"
            explanation = (
                "Prediction resolved to a different CWE in the same "
                "CWE-1000 pillar."
            )
        else:
            error_category = "different_pillar"
            explanation = (
                "Prediction resolved to a CWE in a different CWE-1000 pillar."
            )

        return {
            "normalized_label": normalized_label,
            "resolved_cwe": resolved_cwe,
            "resolution_method": resolution_method,
            "layer_1_result": "incorrect",
            "layer_2_error_category": error_category,
            "explanation": explanation,
        }

    if normalized_label in broad_term_map:
        compatible_cwes = broad_term_map[normalized_label]

        if (
            ground_truth_set & compatible_cwes
            or share_pillar(
                compatible_cwes,
                ground_truth_set,
                cwe_to_pillar,
            )
        ):
            error_category = "same_pillar_wrong_cwe"
            explanation = (
                "Prediction is a broad or ambiguous weakness term associated "
                "with the correct pillar, but it is not an exact CWE."
            )
        else:
            error_category = "different_pillar"
            explanation = (
                "Recognised broad term is not associated with the "
                "ground-truth pillar."
            )

        return {
            "normalized_label": normalized_label,
            "resolved_cwe": None,
            "resolution_method": "BROAD_OR_AMBIGUOUS",
            "layer_1_result": "incorrect",
            "layer_2_error_category": error_category,
            "explanation": explanation,
        }

    return {
        "normalized_label": normalized_label,
        "resolved_cwe": None,
        "resolution_method": resolution_method,
        "layer_1_result": "incorrect",
        "layer_2_error_category": "unmapped_or_absent",
        "explanation": (
            "Prediction was null, vague, unsupported, or could not be "
            "mapped safely to a CWE or recognised weakness pillar."
        ),
    }


def calculate_summary(
    scored_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for record in scored_records:
        key = (
            record["model"],
            record["prompt_condition"],
        )
        grouped[key].append(record)

    summary_rows: list[dict[str, Any]] = []

    for (model, prompt_condition), records in sorted(grouped.items()):
        layer_1_counts = Counter(
            record["layer_1_result"]
            for record in records
        )
        layer_2_counts = Counter(
            record["layer_2_error_category"]
            for record in records
            if record["layer_2_error_category"] is not None
        )

        total = len(records)
        correct = layer_1_counts["correct"]
        incorrect = layer_1_counts["incorrect"]

        row = {
            "model": model,
            "prompt_condition": prompt_condition,
            "total": total,
            "correct": correct,
            "incorrect": incorrect,
            "strict_accuracy": correct / total if total else 0.0,
            "same_pillar_wrong_cwe": (
                layer_2_counts["same_pillar_wrong_cwe"]
            ),
            "consequence_not_mechanism": (
                layer_2_counts["consequence_not_mechanism"]
            ),
            "different_pillar": (
                layer_2_counts["different_pillar"]
            ),
            "unmapped_or_absent": (
                layer_2_counts["unmapped_or_absent"]
            ),
        }

        layer_2_total = (
            row["same_pillar_wrong_cwe"]
            + row["consequence_not_mechanism"]
            + row["different_pillar"]
            + row["unmapped_or_absent"]
        )

        if correct + incorrect != total:
            raise ValueError(
                f"Layer 1 totals do not equal total for {model}, "
                f"{prompt_condition}."
            )

        if layer_2_total != incorrect:
            raise ValueError(
                f"Layer 2 totals do not equal incorrect count for {model}, "
                f"{prompt_condition}."
            )

        summary_rows.append(row)

    return summary_rows


def main() -> None:
    model_results = load_json(RESULTS_FILE)
    alias_database = load_json(ALIASES_FILE)
    vocabulary = load_json(VOCAB_FILE)

    cwe_to_pillar = {
        item["cwe_id"]: item["cwe_1000_pillar"]
        for item in vocabulary["cwes"]
    }

    alias_to_cwe = build_alias_resolver(alias_database)
    broad_term_map = build_broad_term_map(alias_database)

    scored_records: list[dict[str, Any]] = []

    for record in model_results:
        predicted_label = (
            record.get("extracted", {})
            .get("vulnerability_type")
        )
        ground_truth_cwes = (
            record.get("ground_truth", {})
            .get("cwe_ids")
            or []
        )

        classification = classify_prediction(
            predicted_label=predicted_label,
            ground_truth_cwes=ground_truth_cwes,
            alias_to_cwe=alias_to_cwe,
            broad_term_map=broad_term_map,
            cwe_to_pillar=cwe_to_pillar,
        )

        scored_records.append({
            "cve_id": record["cve_id"],
            "model": record["model"],
            "prompt_condition": record["prompt_condition"],
            "predicted_label": predicted_label,
            "normalized_label": classification["normalized_label"],
            "resolved_cwe": classification["resolved_cwe"],
            "resolution_method": classification["resolution_method"],
            "ground_truth_cwes": ground_truth_cwes,
            "ground_truth_pillars": sorted({
                cwe_to_pillar[cwe]
                for cwe in ground_truth_cwes
                if cwe in cwe_to_pillar
            }),
            "layer_1_result": classification["layer_1_result"],
            "layer_2_error_category": (
                classification["layer_2_error_category"]
            ),
            "explanation": classification["explanation"],
        })

    summary_rows = calculate_summary(scored_records)

    DETAILS_OUTPUT.write_text(
        json.dumps(
            scored_records,
            indent=2,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )

    summary_payload = {
        "framework": {
            "layer_1": [
                "correct",
                "incorrect",
            ],
            "layer_2_for_incorrect": [
                "same_pillar_wrong_cwe",
                "consequence_not_mechanism",
                "different_pillar",
                "unmapped_or_absent",
            ],
            "main_metric": (
                "strict_accuracy = correct / total"
            ),
            "strict_rule": (
                "Only predictions resolving to a ground-truth CWE count "
                "as correct."
            ),
        },
        "records_scored": len(scored_records),
        "results": summary_rows,
    }

    SUMMARY_OUTPUT.write_text(
        json.dumps(
            summary_payload,
            indent=2,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=summary_rows[0].keys(),
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    print(
        json.dumps(
            summary_payload,
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
