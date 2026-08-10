"""
fetch_sample_cpes.py

Day 1/2 support script: pull a small batch of real CVEs from the NVD API 2.0
and print out their raw CPE match data, so we can SEE what "affected
component" ground truth actually looks like before building matching logic
on top of it.

This does NOT build the dataset (that's Day 1's build_dataset.py). This is
purely an inspection tool.
"""

import requests
import json
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves(limit=10, start_index=0, pub_start_date=None, pub_end_date=None):
    """Fetch a page of CVEs from the NVD API 2.0 (no API key = lower rate limit, fine for a small inspection batch)."""
    params = {"resultsPerPage": limit, "startIndex": start_index}
    if pub_start_date and pub_end_date:
        params["pubStartDate"] = pub_start_date
        params["pubEndDate"] = pub_end_date
    resp = requests.get(NVD_API_URL, params=params, timeout=60)
    resp.raise_for_status()
    return resp.json()


def get_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def get_cvss_vector(cve):
    """CVSS data can live under metrics.cvssMetricV31 / V30 / V2. Grab the first available."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0]["cvssData"].get("vectorString", "")
    return None


def get_cwe_id(cve):
    weaknesses = cve.get("weaknesses", [])
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("lang") == "en":
                return d.get("value", "")
    return None


def get_cpes(cve):
    """
    Walk configurations -> nodes -> cpeMatch -> criteria.
    'criteria' is the raw CPE 2.3 string, e.g.:
      cpe:2.3:a:apache:struts:2.5.10:*:*:*:*:*:*:*
    Only entries marked 'vulnerable': true are actually affected versions
    (the API also lists non-vulnerable ranges in some configs).
    """
    cpes = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    cpes.append(cpe_match.get("criteria"))
    return cpes


def main():
    # NVD API defaults to oldest-first (CVE ID order), which is useless for
    # inspecting what your actual 500-CVE dataset will look like. Pull a
    # recent window instead.
    pub_start = "2026-05-01T00:00:00.000"
    pub_end = "2026-06-01T00:00:00.000"

    print(f"Fetching 10 CVEs published between {pub_start} and {pub_end}...\n")
    data = fetch_cves(limit=10, pub_start_date=pub_start, pub_end_date=pub_end)
    vulns = data.get("vulnerabilities", [])

    for entry in vulns:
        cve = entry["cve"]
        cve_id = cve["id"]
        desc = get_description(cve)
        cvss = get_cvss_vector(cve)
        cwe = get_cwe_id(cve)
        cpes = get_cpes(cve)

        print(f"=== {cve_id} ===")
        print(f"Description: {desc[:180]}{'...' if len(desc) > 180 else ''}")
        print(f"CVSS vector: {cvss}")
        print(f"CWE: {cwe}")
        print(f"CPEs found ({len(cpes)}):")
        if cpes:
            for c in cpes[:6]:
                print(f"   {c}")
        else:
            print("   (none in this record)")
        print()


if __name__ == "__main__":
    main()