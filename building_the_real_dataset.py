"""
build_dataset.py
==================
Day 3 deliverable: scale Day 1's completeness-filtered fetch loop from
5 records to the full target of 500.

Everything from Day 1/Step 1 is unchanged:
  - get_description(), get_cvss_vector(), get_vulnerability_type() [cwe_id],
    get_attack_vector(), get_cia_impact(), get_affected_components()
  - is_complete(): requires description, cvss_vector, cwe_id, AND genuine
    CPE data specifically (affected_component_source == "cpe" with a
    non-empty affected_cpes_raw list) -- the "affected" fallback alone is
    NOT sufficient, per the scope decision locked 22 June.

TWO THINGS ADDED FOR 500-SCALE (nothing else):

1. RATE LIMITING. NVD allows 5 requests/30s without an API key, 50/30s
   with one. The Day 1 script fired requests back-to-back with no delay,
   which was fine for one page but will get you 403'd at 500-target
   scale. A delay is now inserted between every page request, sized to
   whether NVD_API_KEY is set.

2. AUTOMATIC WINDOW EXTENSION. The proposal's own risk-analysis
   contingency (Section 4.2.2) says: if the dataset doesn't reach target
   size in the current date window, EXTEND THE WINDOW before reducing
   the target below 500. The Day 1 script didn't do this automatically --
   it just gave up at the end of a fixed 60-day window. This version
   keeps extending the window backward in WINDOW_EXTENSION_DAYS steps,
   up to MAX_WINDOW_DAYS, before finally giving up and telling you to
   apply the documented 300-record fallback yourself.

EXPECTED BEHAVIOUR NOTE (flagged previously, worth re-reading now):
requiring genuine CPE data will likely pull a higher proportion of
large, fast-CPE-tagging vendors (IBM, Microsoft, Oracle, etc.) than a
looser filter would. Watch the vendor/CWE breakdown printed at the end
-- if one or two vendors dominate, that's a real finding to write into
your Day 4 Decision Log, not something to silently fix here.
"""

import os
import json
import time
import requests
from collections import Counter
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": API_KEY} if API_KEY else {}

TARGET_COMPLETE = 500            # Day 3's target
INITIAL_WINDOW_DAYS = 90         # starting search window, widened vs Day 1's 5-record test
WINDOW_EXTENSION_DAYS = 90       # how much further back to extend if window is exhausted
MAX_WINDOW_DAYS = 1095           # hard cap: 3 years back, matches "extend before reducing target" contingency
RESULTS_PER_PAGE = 200           # max NVD allows per page is 2000, but smaller pages = more frequent progress feedback
SAVE_EVERY = 50                  # incremental save interval, so a crash mid-run doesn't lose everything

# Rate limit: NVD allows 5 req/30s without a key, 50 req/30s with one.
# Sleep long enough between requests to stay comfortably under that.
REQUEST_DELAY_SECONDS = 0.7 if API_KEY else 6.5

OUTPUT_FILE = "build_dataset_output.json"


# ---------------------------------------------------------------------
# Extraction functions -- unchanged from Day 1
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
    CPE first, "affected" fallback for visibility only (does not satisfy
    completeness on its own -- see is_complete()). Only cpeMatch entries
    with vulnerable=True are kept.
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
    """Unchanged from Step 1: CPE required specifically, "affected" fallback insufficient."""
    return bool(
        record["description"]
        and record["cvss_vector"]
        and record["cwe_id"]
        and record["affected_component_source"] == "cpe"
        and record["affected_cpes_raw"]
    )


def _missing_fields(record):
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


def _save(records, path=OUTPUT_FILE):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4)


def _fetch_page(start_date, end_date, start_index, results_per_page):
    """Single page fetch with retry-on-failure, returns parsed JSON or raises."""
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
    }
    response = None
    for attempt in range(1, 6):
        response = requests.get(NVD_URL, headers=HEADERS, params=params)
        if response.status_code == 200:
            return response.json()
        wait = 10 * attempt
        print(f"  NVD returned {response.status_code}, retrying in {wait}s (attempt {attempt}/5)...")
        time.sleep(wait)
    response.raise_for_status()


# ---------------------------------------------------------------------
# Main fetch loop: paginate within a window; extend window automatically
# if exhausted before reaching target.
# ---------------------------------------------------------------------

def build_dataset(target=TARGET_COMPLETE):
    end_date = datetime.utcnow()
    window_days = INITIAL_WINDOW_DAYS

    complete_records = []
    seen_ids = set()  # prevents duplicates when window extension re-scans CVEs already collected
    examined = 0
    cpe_fallback_count = 0
    last_saved_count = 0

    while len(complete_records) < target and window_days <= MAX_WINDOW_DAYS:
        start_date = end_date - timedelta(days=window_days)
        start_index = 0
        print(f"\n--- Searching window: last {window_days} days "
              f"({start_date.date()} to {end_date.date()}) ---")

        while len(complete_records) < target:
            data = _fetch_page(start_date, end_date, start_index, RESULTS_PER_PAGE)
            time.sleep(REQUEST_DELAY_SECONDS)

            vulns = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            if not vulns:
                print(f"  No more CVEs returned in this window after examining {examined} total.")
                break

            for entry in vulns:
                cve = entry["cve"]

                if cve.get("id") in seen_ids:
                    continue  # already collected/rejected under a narrower window -- don't re-process

                examined += 1
                record = extract_record(cve)
                seen_ids.add(record["cve_id"])

                if is_complete(record):
                    complete_records.append(record)
                    if len(complete_records) % 10 == 0 or len(complete_records) == target:
                        print(f"  [{len(complete_records)}/{target}] complete records found "
                              f"(examined {examined} so far)")
                else:
                    if record["affected_component_source"] == "affected" and record["affected_components"]:
                        cpe_fallback_count += 1

                if len(complete_records) >= target:
                    break

                if len(complete_records) - last_saved_count >= SAVE_EVERY:
                    _save(complete_records)
                    last_saved_count = len(complete_records)
                    print(f"  -- incremental save at {len(complete_records)} records --")

            start_index += RESULTS_PER_PAGE
            if start_index >= total_results:
                print(f"  Reached end of this window ({total_results} total CVEs in it).")
                break

        if len(complete_records) < target:
            window_days += WINDOW_EXTENSION_DAYS
            print(f"Only {len(complete_records)}/{target} found so far. "
                  f"Extending window to {window_days} days and continuing "
                  f"(per proposal's documented contingency)...")

    return complete_records, examined, cpe_fallback_count, window_days


if __name__ == "__main__":
    print(f"Searching for {TARGET_COMPLETE} complete records "
          f"(description + cvss_vector + cwe_id + genuine CPE, all required)...")
    print(f"Rate limit delay: {REQUEST_DELAY_SECONDS}s between requests "
          f"({'with' if API_KEY else 'WITHOUT'} an API key set)\n")

    records, examined, cpe_fallback_count, final_window = build_dataset()

    _save(records)

    print(f"\nExamined {examined} CVEs total to find {len(records)} complete ones.")
    print(f"Final search window: {final_window} days.")
    if cpe_fallback_count:
        print(f"Note: {cpe_fallback_count} CVE(s) had 'affected'-only data and were excluded "
              f"under the CPE-required scope.")
    print(f"Saved to {OUTPUT_FILE}\n")

    print("=" * 70)
    print("DAY 3 'DONE WHEN' CHECK")
    print("=" * 70)
    if len(records) >= TARGET_COMPLETE:
        print(f"PASS: {len(records)}/{TARGET_COMPLETE} complete records, "
              f"all four fields populated, affected_component backed by genuine CPE data.")
    else:
        print(f"FAIL: only {len(records)}/{TARGET_COMPLETE} complete records found, "
              f"even after extending the window to the {MAX_WINDOW_DAYS}-day cap.")
        print(f"Per your proposal's documented contingency (Section 4.2.2): "
              f"apply the 300-record fallback now, and document why in your Decision Log.")

    # ------------------------------------------------------------------
    # Quick diagnostic only -- NOT the full Day 4 deliverable, just an
    # early look at the vendor/CWE concentration risk flagged earlier.
    # ------------------------------------------------------------------
    if records:
        cwe_counts = Counter(r["cwe_id"] for r in records)
        vendor_counts = Counter(r["affected_cpes_raw"][0].split(":")[3] for r in records if r["affected_cpes_raw"])
        print("\n--- Quick diagnostic (not the full Day 4 stats) ---")
        print("Top 5 CWE categories:", cwe_counts.most_common(5))
        print("Top 5 vendors:", vendor_counts.most_common(5))