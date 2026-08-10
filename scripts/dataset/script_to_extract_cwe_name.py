"""
build_dataset.py
==================
Day 3 deliverable: scale Day 1's completeness-filtered fetch loop from
5 records to the full target of 500.

Everything from Day 1/Step 1 is unchanged:
  - get_description(), get_cvss_vector(), get_vulnerability_types() [cwe_ids],
    get_attack_vector(), get_cia_impact(), get_affected_components()
  - is_complete(): requires description, cvss_vector, a non-empty cwe_ids list,
    AND genuine
    CPE data specifically (affected_component_source == "cpe" with a
    non-empty affected_cpes_raw list) -- the "affected" fallback alone is
    NOT sufficient, per the scope decision locked 22 June.

SAMPLING REDESIGN (replaces the old growing-window approach entirely):

The original version queried one large, growing date window and stopped
the moment it hit 500 complete records. In practice this meant the
script filled its entire quota from a 2-day mass-disclosure batch
(Linux kernel CVEs) sitting at the OLDEST edge of the window, because
NVD returns results oldest-first within any date range and the script
never got further than that. The result was a dataset that was neither
"recent" (as the proposal requires) nor diverse (over a third of it was
2-3 vendors from a single 48-hour window).

Fixed by:
1. FIXED ANCHOR DATE. END_DATE is a fixed cutoff (31 May 2026), not
   "now" -- deliberately excluding the most recent ~3 weeks of CVEs,
   which likely haven't finished NVD enrichment yet (the same
   enrichment-lag risk the proposal already names in 4.2.2, applied
   proactively).
2. CHUNK-WALKING. Instead of one big window, the search walks backward
   from END_DATE in CHUNK_DAYS-day slices, checking each slice fully
   before stepping further back. This also incidentally fixes a second,
   separate bug: NVD enforces a hard 120-day cap on any single
   pubStartDate/pubEndDate request, and the old window-extension logic
   would have exceeded that the first time it was actually needed.
3. PER-DAY CAP. MAX_PER_DAY limits how many complete records can come
   from any single calendar published-date, so no single mass-batch day
   can dominate the dataset the way the Linux kernel batch did before.

RATE LIMITING (unchanged from the previous version): NVD allows 5
requests/30s without an API key, 50/30s with one. REQUEST_DELAY_SECONDS
is sized accordingly. RESULTS_PER_PAGE is set to NVD's actual max
(2000) to minimise the number of page-fetches, and therefore the total
time spent sleeping between requests, for a given amount of CVE data.
"""

import os
import csv
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
END_DATE = datetime(2026, 5, 31)  # fixed anchor -- deliberately excludes likely-unenriched recent CVEs
CHUNK_DAYS = 2                    # width of each backward-walking search slice
MAX_PER_DAY = 20                  # cap on complete records taken from any single published-date
MAX_WINDOW_DAYS = 1095            # hard cap: 3 years back, before giving up and applying the 300-record fallback
RESULTS_PER_PAGE = 2000           # NVD's actual max -- minimises page-fetch count (and sleep time) per chunk
SAVE_EVERY = 50                   # incremental save interval, so a crash mid-run doesn't lose everything

# Rate limit: NVD allows 5 req/30s without a key, 50 req/30s with one.
# Sleep long enough between requests to stay comfortably under that.
REQUEST_DELAY_SECONDS = 0.7 if API_KEY else 6.5

OUTPUT_FILE = "dataset_with_cwe_names.json"

CWE_MAPPING_FILE = "cwe_id_name_mapping.csv"  # see load_cwe_mapping() docstring for how to obtain this


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


def get_vulnerability_types(cve):
    """
    Returns a LIST of CWE IDs, not a single value -- NVD permits assigning
    more than one Primary weakness type to the same CVE when it genuinely
    exhibits more than one (e.g. both an injection flaw and an auth bypass).
    Collapsing to a single value would silently discard real ground-truth
    signal.

    Priority order, per the locked CWE-precedence decision: NVD-Primary,
    NVD-Secondary, CNA-Primary, CNA-Secondary. ALL valid CWEs within the
    first tier that has any match are returned together; lower tiers are
    only used as a fallback when the higher tier is completely empty (e.g.
    NVD hasn't reviewed this CVE yet), never to supplement it.
    """
    invalid_values = {"NVD-CWE-Other", "NVD-CWE-noinfo"}

    def cwes_in_tier(source_filter, type_filter):
        found = []
        for weakness in cve.get("weaknesses", []):
            is_nvd = weakness.get("source") == "nvd@nist.gov"
            if source_filter == "nvd" and not is_nvd:
                continue
            if source_filter == "cna" and is_nvd:
                continue
            if weakness.get("type") != type_filter:
                continue
            for d in weakness.get("description", []):
                if d.get("lang") == "en" and d.get("value") not in invalid_values:
                    found.append(d["value"])
        return found

    for source, wtype in [("nvd", "Primary"), ("nvd", "Secondary"),
                           ("cna", "Primary"), ("cna", "Secondary")]:
        matches = cwes_in_tier(source, wtype)
        if matches:
            return matches
    return []


def load_cwe_mapping(path=CWE_MAPPING_FILE):
    """
    Loads a local CWE-ID -> name lookup table.

    Why this exists: the NVD API's `weaknesses` field only ever returns bare
    CWE IDs (e.g. "CWE-79"), never the human-readable name. NVD does not
    provide names -- that's MITRE's CWE database, a completely separate
    source. So this is NOT parsed out of the NVD response; it's a static
    table loaded once and joined against cwe_ids after extraction.

    How to get the CSV:
      1. https://cwe.mitre.org/data/downloads.html
      2. Download "Software Development" (or "Research Concepts") view --
         either includes every CWE ID with its name.
      3. Unzip it. You'll get a CSV with (at least) columns 'CWE-ID' and
         'Name'. Save/rename it to CWE_MAPPING_FILE above, same folder as
         this script.

    Returns: dict mapping "CWE-79" -> "Cross-site Scripting (XSS)". If the
    file is missing, returns an empty dict and get_cwe_names() will fall
    back to None for every ID rather than crashing the whole run --
    resolving names is enrichment, not a completeness requirement, so it
    should never be able to take down the fetch loop.
    """
    if not os.path.exists(path):
        print(f"  WARNING: {path} not found -- CWE names will be left as None. "
              f"See load_cwe_mapping() docstring to fix this.")
        return {}

    mapping = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cwe_id = row.get("CWE-ID", "").strip()
            name = row.get("Name", "").strip()
            if cwe_id and name:
                # MITRE's CSV stores bare numbers ("79"); NVD's weakness
                # values are prefixed ("CWE-79") -- normalise to NVD's form
                # so lookups against cwe_ids work directly, no per-call fixup.
                key = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
                mapping[key] = name
    return mapping


def get_cwe_names(cwe_ids, cwe_mapping):
    """
    Resolves a list of CWE IDs to names via the local mapping, preserving
    order and length so cwe_names[i] always corresponds to cwe_ids[i] --
    important since a record can carry more than one CWE (see
    get_vulnerability_types()). Unresolved IDs map to None rather than being
    dropped, so the two lists never drift out of alignment.
    """
    return [cwe_mapping.get(cwe_id) for cwe_id in cwe_ids]


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


def extract_record(cve, cwe_mapping=None):
    cia = get_cia_impact(cve)
    affected = get_affected_components(cve)
    cwe_ids = get_vulnerability_types(cve)
    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "description": get_description(cve),
        "cvss_vector": get_cvss_vector(cve),
        "cwe_ids": cwe_ids,
        "cwe_names": get_cwe_names(cwe_ids, cwe_mapping or {}),
        "attack_vector": get_attack_vector(cve),
        "confidentiality_impact": cia["confidentiality_impact"],
        "integrity_impact": cia["integrity_impact"],
        "availability_impact": cia["availability_impact"],
        "affected_component_source": affected["source"],
        "affected_components": affected["components"],
        "affected_cpes_raw": affected["raw_cpes"],
    }


def is_complete(record):
    """Unchanged from Step 1 in spirit: CPE required specifically, "affected"
    fallback insufficient. cwe_ids must be a non-empty list (explicit check,
    not relying on bool([]) being falsy by coincidence)."""
    return bool(
        record["description"]
        and record["cvss_vector"]
        and len(record["cwe_ids"]) > 0
        and record["affected_component_source"] == "cpe"
        and record["affected_cpes_raw"]
    )


def _missing_fields(record):
    missing = []
    if not record["description"]:
        missing.append("description")
    if not record["cvss_vector"]:
        missing.append("cvss_vector")
    if not record["cwe_ids"]:
        missing.append("cwe_ids")
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
# Main fetch loop: walk backward from END_DATE in CHUNK_DAYS-day slices,
# capping how many complete records any single calendar day can
# contribute, until target is reached or MAX_WINDOW_DAYS is exhausted.
# ---------------------------------------------------------------------

def build_dataset(target=TARGET_COMPLETE):
    # Loaded once, outside the fetch loop -- this is a static lookup table,
    # not per-CVE network calls. See load_cwe_mapping() docstring.
    cwe_mapping = load_cwe_mapping()

    chunk_end = END_DATE
    total_days_walked = 0

    complete_records = []
    seen_ids = set()  # prevents duplicates if a CVE is ever seen across overlapping chunk boundaries
    examined = 0
    cpe_fallback_count = 0
    rejected_count = 0
    day_quota_excluded_count = 0  # complete records skipped purely for hitting MAX_PER_DAY, not data quality
    multi_cwe_count = 0  # complete records where NVD itself assigned more than one weakness type
    failure_reasons = Counter()  # why incomplete records failed is_complete(), for Decision Log insight
    day_counts = Counter()  # published date (YYYY-MM-DD) -> how many complete records taken from that day
    last_saved_count = 0

    while len(complete_records) < target and total_days_walked < MAX_WINDOW_DAYS:
        chunk_start = chunk_end - timedelta(days=CHUNK_DAYS)
        start_index = 0
        print(f"\n--- Searching chunk: {chunk_start.date()} to {chunk_end.date()} ---")

        while True:
            data = _fetch_page(chunk_start, chunk_end, start_index, RESULTS_PER_PAGE)
            time.sleep(REQUEST_DELAY_SECONDS)

            vulns = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            if not vulns:
                print(f"  No CVEs returned in this chunk.")
                break

            for entry in vulns:
                cve = entry["cve"]

                if cve.get("id") in seen_ids:
                    continue  # already processed -- shouldn't normally happen with non-overlapping chunks

                if cve.get("vulnStatus") == "Rejected":
                    # Rejected CVE IDs can retain stale CVSS/CWE/CPE data from before
                    # rejection, which would otherwise pass is_complete() while the
                    # description itself no longer describes a real vulnerability.
                    seen_ids.add(cve.get("id"))
                    rejected_count += 1
                    continue

                examined += 1
                record = extract_record(cve, cwe_mapping)
                seen_ids.add(record["cve_id"])

                if is_complete(record):
                    pub_day = record["published"][:10] if record["published"] else "unknown"
                    if day_counts[pub_day] >= MAX_PER_DAY:
                        # Good record, but this day has already hit its quota -- skip
                        # for diversity reasons, not data-quality reasons. Tracked
                        # separately so it doesn't get confused with failure_reasons.
                        day_quota_excluded_count += 1
                        continue
                    day_counts[pub_day] += 1
                    complete_records.append(record)
                    if len(record["cwe_ids"]) > 1:
                        # Measures how often NVD itself assigns more than one weakness
                        # type to a single CVE -- evidence for the Decision Log rather
                        # than a guess about how common this actually is.
                        multi_cwe_count += 1
                    if len(complete_records) % 10 == 0 or len(complete_records) == target:
                        print(f"  [{len(complete_records)}/{target}] complete records found "
                              f"(examined {examined} so far)")
                else:
                    if record["affected_component_source"] == "affected" and record["affected_components"]:
                        cpe_fallback_count += 1
                    # Track every reason this record failed, not just the CPE-fallback
                    # case -- a record can be missing more than one field at once, so
                    # these counts can sum to more than the number of incomplete records.
                    if not record["description"]:
                        failure_reasons["missing_description"] += 1
                    if not record["cvss_vector"]:
                        failure_reasons["missing_cvss_vector"] += 1
                    if not record["cwe_ids"]:
                        failure_reasons["missing_cwe_ids"] += 1
                    if record["affected_component_source"] != "cpe" or not record["affected_cpes_raw"]:
                        failure_reasons["missing_cpe"] += 1

                if len(complete_records) >= target:
                    break

                if len(complete_records) - last_saved_count >= SAVE_EVERY:
                    _save(complete_records)
                    last_saved_count = len(complete_records)
                    print(f"  -- incremental save at {len(complete_records)} records --")

            if len(complete_records) >= target:
                break

            start_index += RESULTS_PER_PAGE
            if start_index >= total_results:
                print(f"  Reached end of this chunk ({total_results} total CVEs in it).")
                break

        chunk_end = chunk_start  # step backward for the next iteration
        total_days_walked += CHUNK_DAYS

        if len(complete_records) < target:
            print(f"{len(complete_records)}/{target} so far. Walking back further "
                  f"({total_days_walked} days back from {END_DATE.date()} so far)...")

    stats = {
        "examined": examined,
        "rejected_count": rejected_count,
        "cpe_fallback_count": cpe_fallback_count,
        "failure_reasons": failure_reasons,
        "day_quota_excluded_count": day_quota_excluded_count,
        "multi_cwe_count": multi_cwe_count,
        "distinct_days_contributed": len(day_counts),
        "max_from_single_day": max(day_counts.values()) if day_counts else 0,
        "days_walked": total_days_walked,
        "search_start_date": chunk_end.date(),
        "search_end_date": END_DATE.date(),
        "target_reached": len(complete_records) >= target,
    }
    return complete_records, stats



if __name__ == "__main__":
    print(f"Searching for {TARGET_COMPLETE} complete records "
          f"(description + cvss_vector + cwe_ids + genuine CPE, all required)...")
    print(f"Anchored at {END_DATE.date()}, walking backward in {CHUNK_DAYS}-day chunks, "
          f"max {MAX_PER_DAY} per calendar day.")
    print(f"Rate limit delay: {REQUEST_DELAY_SECONDS}s between requests "
          f"({'with' if API_KEY else 'WITHOUT'} an API key set)\n")

    records, stats = build_dataset()

    _save(records)

    total_seen = stats["examined"] + stats["rejected_count"]
    completion_rate = (len(records) / stats["examined"] * 100) if stats["examined"] else 0.0

    print("\n" + "=" * 70)
    print("SEARCH SUMMARY")
    print("=" * 70)
    print(f"Date range searched:      {stats['search_start_date']} to {stats['search_end_date']} "
          f"({stats['days_walked']} days walked back)")
    print(f"Total CVEs seen:          {total_seen}")
    print(f"  - Rejected (skipped):   {stats['rejected_count']}")
    print(f"  - Examined (extracted): {stats['examined']}")
    print(f"Complete records:         {len(records)} / {stats['examined']} examined "
          f"({completion_rate:.1f}% completion rate)")
    print(f"Incomplete records:      {stats['examined'] - len(records)}")
    if stats["failure_reasons"]:
        print("\nWhy incomplete records failed (counts can overlap -- a record can be")
        print("missing more than one field):")
        for reason, count in stats["failure_reasons"].most_common():
            print(f"  - {reason}: {count}")
    if stats["cpe_fallback_count"]:
        print(f"\nOf those, {stats['cpe_fallback_count']} had 'affected'-only data (no genuine "
              f"CPE match) and were excluded under the CPE-required scope.")
    print(f"\nDiversity check (per-day cap = {MAX_PER_DAY}):")
    print(f"  - Distinct published dates contributing: {stats['distinct_days_contributed']}")
    print(f"  - Max records from any single day:       {stats['max_from_single_day']}")
    if stats["day_quota_excluded_count"]:
        print(f"  - Otherwise-complete records skipped on day-quota alone: "
              f"{stats['day_quota_excluded_count']} (good records, just over that day's cap)")
    print(f"\nMulti-CWE check: {stats['multi_cwe_count']} / {len(records)} complete records "
          f"had more than one CWE assigned within their winning source/type tier "
          f"(these records carry multiple entries in cwe_ids, not a single value).")
    print(f"\nOutput saved to: {OUTPUT_FILE}")

    print("\n" + "=" * 70)
    print("DAY 3 'DONE WHEN' CHECK")
    print("=" * 70)
    if stats["target_reached"]:
        print(f"PASS: {len(records)}/{TARGET_COMPLETE} complete records, "
              f"all four fields populated, affected_component backed by genuine CPE data.")
    else:
        print(f"FAIL: only {len(records)}/{TARGET_COMPLETE} complete records found, "
              f"even after walking back {MAX_WINDOW_DAYS} days from {END_DATE.date()}.")
        print(f"Per your proposal's documented contingency (Section 4.2.2): "
              f"apply the 300-record fallback now, and document why in your Decision Log.")

    # ------------------------------------------------------------------
    # Quick diagnostic only -- NOT the full Day 4 deliverable, just an
    # early look at the vendor/CWE concentration risk flagged earlier.
    # ------------------------------------------------------------------
    if records:
        cwe_counts = Counter(cwe for r in records for cwe in r["cwe_ids"])
        vendor_counts = Counter(r["affected_cpes_raw"][0].split(":")[3] for r in records if r["affected_cpes_raw"])
        print("\n--- Quick diagnostic (not the full Day 4 stats) ---")
        print("Top 5 CWE categories:", cwe_counts.most_common(5))
        print("Top 5 vendors:", vendor_counts.most_common(5))