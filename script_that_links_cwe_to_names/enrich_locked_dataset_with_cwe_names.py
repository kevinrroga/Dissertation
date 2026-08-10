"""
enrich_locked_dataset_with_cwe_names.py
========================================
Adds a `cwe_names` field to an already-locked dataset (e.g.
dataset_v1_locked_24jun.json) WITHOUT touching the NVD API at all.

Why this exists, instead of just re-running build_dataset.py:
Re-running the fetch pulls whatever NVD currently has, which drifts over
time (enrichment edits, pagination differences) -- confirmed on this
project's data: re-running produced a 500-record set that shared only 475
CVEs with the original locked file. That's fine if you WANT a fresh pull,
but it silently breaks "same 500 CVEs, just with one more field," which is
what was actually wanted here.

This script instead does a pure local join: read the already-locked file,
look up each record's EXISTING cwe_ids against the local MITRE CWE mapping
CSV, and attach cwe_names. The CVE set, order, and every other field are
byte-for-byte unchanged. No network calls.

Usage:
    python enrich_locked_dataset_with_cwe_names.py

Edit the three constants below if your filenames differ.
"""

import os
import csv
import json

INPUT_FILE = "dataset_v1_locked_24jun.json"          # the dataset to enrich -- untouched except for the new field
CWE_MAPPING_FILE = "cwe_id_name_mapping.csv"          # from https://cwe.mitre.org/data/downloads.html
OUTPUT_FILE = "dataset_v1_locked_24jun_with_cwe_names.json"  # new file -- INPUT_FILE is never overwritten


def load_cwe_mapping(path=CWE_MAPPING_FILE):
    """Same logic as in dataset_multiple_cwes.py -- kept identical on
    purpose so both scripts resolve names the same way."""
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"{path} not found. Download the CWE list CSV from "
            f"https://cwe.mitre.org/data/downloads.html and place it here "
            f"before running this script -- there is no safe fallback for "
            f"a missing mapping when the whole point of the run is to add names."
        )
    mapping = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cwe_id = row.get("CWE-ID", "").strip()
            name = row.get("Name", "").strip()
            if cwe_id and name:
                key = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
                mapping[key] = name
    return mapping


def get_cwe_names(cwe_ids, cwe_mapping):
    return [cwe_mapping.get(cwe_id) for cwe_id in cwe_ids]


def main():
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"{INPUT_FILE} not found in this directory.")

    with open(INPUT_FILE, encoding="utf-8") as f:
        records = json.load(f)

    cwe_mapping = load_cwe_mapping()
    print(f"Loaded {len(cwe_mapping)} CWE ID->name entries from {CWE_MAPPING_FILE}")
    print(f"Enriching {len(records)} records from {INPUT_FILE} (unchanged otherwise)...")

    unresolved = 0
    for record in records:
        cwe_ids = record.get("cwe_ids", [])
        names = get_cwe_names(cwe_ids, cwe_mapping)
        record["cwe_names"] = names
        unresolved += sum(1 for n in names if n is None)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4)

    # ------------------------------------------------------------------
    # Verification -- confirm the CVE set genuinely didn't change, since
    # that's the entire point of doing it this way instead of re-fetching.
    # ------------------------------------------------------------------
    original_ids = set()
    with open(INPUT_FILE, encoding="utf-8") as f:
        original_ids = {r["cve_id"] for r in json.load(f)}
    new_ids = {r["cve_id"] for r in records}

    print(f"\nDone. Output: {OUTPUT_FILE}")
    print(f"Record count: {len(records)}")
    print(f"CVE set unchanged from {INPUT_FILE}: {original_ids == new_ids}")
    print(f"Records with at least one unresolved (None) cwe_name: {unresolved}")
    if unresolved:
        print("  -> Likely deprecated/withdrawn CWE IDs not in the current MITRE "
              "table, or a formatting mismatch. Worth spot-checking a few by hand "
              "before treating this file as final.")


if __name__ == "__main__":
    main()