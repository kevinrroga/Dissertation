"""
build_dataset.py
==================
Fetches 5 complete CVE records from the NVD API, combining all per-field
extraction functions into one script with a completeness filter and
pagination loop.

Completeness requires: description, cvss_vector, cwe_id, and genuine CPE
data (affected_component_source == "cpe" with a non-empty raw_cpes list).
The "affected" fallback alone is not sufficient — a CVE without a CPE string
cannot be scored by the affected-component matcher.

Note: CPE enrichment is not applied uniformly across all NVD entries, so a
wider WINDOW_DAYS may be needed to fill the target. Watch the
"examined vs. complete" ratio printed at the end.
"""

import os
import json
import time
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": API_KEY} if API_KEY else {}

TARGET_COMPLETE = 5          # fetch this many complete records
WINDOW_DAYS = 60             # how far back to search if one page isn't enough
RESULTS_PER_PAGE = 50        # CVEs fetched per API call while searching for complete ones


# ---------------------------------------------------------------------
# Extraction functions
# ---------------------------------------------------------------------

def get_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return None


def get_cvss_vector(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0]["cvssData"].get("vectorString")
    return None


def get_vulnerability_type(cve):
    invalid_values = {"NVD-CWE-Other", "NVD-CWE-noinfo"}
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            if d.get("lang") == "en" and d.get("value") not in invalid_values:
                return d["value"]
    return None


def get_attack_vector(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0]["cvssData"].get("attackVector")
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        return entries[0]["cvssData"].get("accessVector")
    return None


def get_cia_impact(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss = entries[0]["cvssData"]
            return {
                "confidentiality_impact": cvss.get("confidentialityImpact"),
                "integrity_impact": cvss.get("integrityImpact"),
                "availability_impact": cvss.get("availabilityImpact"),
            }
    return {"confidentiality_impact": None, "integrity_impact": None, "availability_impact": None}


def get_affected_components(cve):
    """
    Returns BOTH a human-readable "vendor product" list (for spot-checking)
    AND the raw CPE 2.3 criteria strings (for the affected-component matcher, which
    parses vendor/product directly out of the cpe:2.3:... format).

    The "affected" fallback is still extracted here for visibility/
    debugging in the saved record, but as of the scope change it no
    longer counts toward completeness on its own -- see is_complete().

    FIX (carried over from earlier version): only cpeMatch entries with
    vulnerable=True are kept. NVD configurations frequently include
    non-vulnerable "runs on this platform" CPEs alongside the actual
    vulnerable component -- including those would corrupt the ground
    truth.
    """
    components = []
    raw_cpes = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") is not True:
                    continue
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    pair = f"{parts[3].replace('_', ' ')} {parts[4].replace('_', ' ')}"
                    if pair not in components:
                        components.append(pair)
                    if criteria not in raw_cpes:
                        raw_cpes.append(criteria)
    if components:
        return {"source": "cpe", "components": components, "raw_cpes": raw_cpes}

    for affected_entry in cve.get("affected", []):
        for ad in affected_entry.get("affectedData", []):
            pair = f"{ad.get('vendor', '')} {ad.get('product', '')}".strip()
            if pair and pair not in components:
                components.append(pair)
    return {"source": "affected", "components": components, "raw_cpes": []}


def extract_record(cve):
    cia = get_cia_impact(cve)
    affected = get_affected_components(cve)
    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "description": get_description(cve),
        "cvss_vector": get_cvss_vector(cve),
        "cwe_id": get_vulnerability_type(cve),
        "attack_vector": get_attack_vector(cve),
        "confidentiality_impact": cia["confidentiality_impact"],
        "integrity_impact": cia["integrity_impact"],
        "availability_impact": cia["availability_impact"],
        "affected_component_source": affected["source"],
        "affected_components": affected["components"],
        "affected_cpes_raw": affected["raw_cpes"],
    }


def is_complete(record):
    """
    Completeness rule: description, cvss_vector, cwe_id must all be non-empty,
    AND the affected-component data must be genuine CPE data specifically --
    affected_component_source == "cpe" with a non-empty raw_cpes list.

    The "affected" fallback (source == "affected") no longer satisfies
    completeness on its own. It is still extracted and saved in every
    record for reference, but a CVE with only "affected" data and no
    CPE match is excluded from the dataset, because the affected-component
    matcher requires a CPE string to score against.
    """
    return bool(
        record["description"]
        and record["cvss_vector"]
        and record["cwe_id"]
        and record["affected_component_source"] == "cpe"
        and record["affected_cpes_raw"]
    )


def _missing_fields(record):
    """Diagnostic helper: which field(s) caused this record to fail completeness."""
    missing = []
    if not record["description"]:
        missing.append("description")
    if not record["cvss_vector"]:
        missing.append("cvss_vector")
    if not record["cwe_id"]:
        missing.append("cwe_id")
    if record["affected_component_source"] != "cpe" or not record["affected_cpes_raw"]:
        missing.append(f"cpe (source was '{record['affected_component_source']}')")
    return missing


# ---------------------------------------------------------------------
# Fetch loop: keep pulling pages until we have TARGET_COMPLETE records
# ---------------------------------------------------------------------

def build_dataset(target=TARGET_COMPLETE):
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=WINDOW_DAYS)
    base_params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
    }

    complete_records = []
    examined = 0
    cpe_fallback_count = 0  # records that had SOME affected data, just not CPE -- track this, it's diagnostic
    start_index = 0

    while len(complete_records) < target:
        params = {**base_params, "resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}

        for attempt in range(1, 6):
            response = requests.get(NVD_URL, headers=HEADERS, params=params)
            if response.status_code in (200,):
                break
            wait = 10 * attempt
            print(f"  NVD returned {response.status_code}, retrying in {wait}s (attempt {attempt}/5)...")
            time.sleep(wait)
        response.raise_for_status()

        data = response.json()

        vulns = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        if not vulns:
            print(f"Ran out of CVEs in the {WINDOW_DAYS}-day window after examining {examined}.")
            break

        for entry in vulns:
            cve = entry["cve"]
            record = extract_record(cve)
            examined += 1

            if is_complete(record):
                complete_records.append(record)
                print(f"  [{len(complete_records)}/{target}] {record['cve_id']} -- COMPLETE (cpe)")
            else:
                if record["affected_component_source"] == "affected" and record["affected_components"]:
                    cpe_fallback_count += 1
                missing = _missing_fields(record)
                print(f"         {record['cve_id']} -- skipped, missing: {missing}")

            if len(complete_records) >= target:
                break

        start_index += RESULTS_PER_PAGE
        if start_index >= total_results:
            print(f"Reached the end of the {WINDOW_DAYS}-day window ({total_results} total CVEs available).")
            break

    return complete_records, examined, cpe_fallback_count


if __name__ == "__main__":
    print(f"Searching for {TARGET_COMPLETE} complete records (CPE required, 'affected'-only no longer counts)...\n")
    records, examined, cpe_fallback_count = build_dataset()

    with open("build_dataset_output.json", "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4)

    print(f"\nExamined {examined} CVEs total to find {len(records)} complete ones.")
    if cpe_fallback_count:
        print(f"Note: {cpe_fallback_count} CVE(s) had 'affected'-only data and were excluded "
              f"under the new CPE-required scope -- these would have counted under the old rule.")
    print(f"Saved to build_dataset_output.json\n")

    print("=" * 70)
    print("DATASET BUILD CHECK")
    print("=" * 70)
    if len(records) == TARGET_COMPLETE:
        print(f"PASS: {TARGET_COMPLETE}/{TARGET_COMPLETE} records have all 4 fields populated, "
              f"affected_component backed by genuine CPE data.")
    else:
        print(f"FAIL: only found {len(records)}/{TARGET_COMPLETE} complete records "
              f"in the {WINDOW_DAYS}-day window. Widen WINDOW_DAYS and retry.")