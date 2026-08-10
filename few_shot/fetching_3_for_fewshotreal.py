"""
simple_fetch_examples.py
========================
SELF-CONTAINED. Does not import from build_dataset.py or anything else.
Fetches complete CVEs from outside your locked 500, spread across attack
vector and CIA shape, and prints them so you can pick your few-shot examples.

Just needs: requests, python-dotenv (optional, for API key), and your
locked dataset file in the same folder.

Run:  python simple_fetch_examples.py
"""

import os
import json
import time
import requests
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict

_ROOT = Path(__file__).resolve().parent.parent.parent

# ---------------- config ----------------
LOCKED_DATASET = str(_ROOT / "data/datasets/dataset_v1_locked_24jun.json")
OUTPUT = str(_ROOT / "data/prompts/diverse_candidates.json")
WINDOW_DAYS = 30          # SAFE: well under NVD's 120-day hard limit
POOL_TARGET = 25          # how many diverse candidates to collect
MAX_PER_SHAPE = 2         # don't over-collect the same (AV, CIA) combo
RESULTS_PER_PAGE = 50

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")            # set in .env or leave unset
HEADERS = {"apiKey": API_KEY} if API_KEY else {}


# ---------------- extraction (inline, no external file) ----------------
def get_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return None

def get_cvss_block(cve):
    m = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if m.get(key):
            return m[key][0]["cvssData"], key
    if m.get("cvssMetricV2"):
        return m["cvssMetricV2"][0]["cvssData"], "cvssMetricV2"
    return None, None

def get_cwe(cve):
    invalid = {"NVD-CWE-Other", "NVD-CWE-noinfo"}
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value") not in invalid:
                return d["value"]
    return None

def get_cpes(cve):
    raw, readable = [], []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") is not True:
                    continue
                crit = match.get("criteria", "")
                parts = crit.split(":")
                if len(parts) >= 5:
                    pair = f"{parts[3].replace('_',' ')} {parts[4].replace('_',' ')}"
                    if pair not in readable:
                        readable.append(pair)
                    if crit not in raw:
                        raw.append(crit)
    return readable, raw

def extract(cve):
    cvss, _ = get_cvss_block(cve)
    readable, raw = get_cpes(cve)
    rec = {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "description": get_description(cve),
        "cvss_vector": cvss.get("vectorString") if cvss else None,
        "cwe_id": get_cwe(cve),
        "attack_vector": (cvss.get("attackVector") or cvss.get("accessVector")) if cvss else None,
        "confidentiality_impact": cvss.get("confidentialityImpact") if cvss else None,
        "integrity_impact": cvss.get("integrityImpact") if cvss else None,
        "availability_impact": cvss.get("availabilityImpact") if cvss else None,
        "affected_components": readable,
        "affected_cpes_raw": raw,
    }
    return rec

def is_complete(r):
    return bool(
        r["description"] and r["cvss_vector"] and r["cwe_id"]
        and r["affected_cpes_raw"]
    )


# ---------------- main fetch ----------------
def main():
    with open(LOCKED_DATASET, encoding="utf-8") as f:
        locked = {r["cve_id"] for r in json.load(f)}
    print(f"Excluding {len(locked)} locked CVE IDs.")

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=WINDOW_DAYS)
    base = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
    }
    print(f"Window: {base['pubStartDate']}  ->  {base['pubEndDate']}  ({WINDOW_DAYS} days)\n")

    kept, examined, start_index = [], 0, 0
    shapes = defaultdict(int)

    while len(kept) < POOL_TARGET:
        params = {**base, "resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}
        r = requests.get(NVD_URL, headers=HEADERS, params=params, timeout=30)

        if r.status_code != 200:
            print(f"NVD returned {r.status_code}. Body: {r.text[:200]}")
            print("If this is 404, your date window is likely too big or in the future.")
            break

        data = r.json()
        vulns = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)
        if not vulns:
            print("No more CVEs in window."); break

        for entry in vulns:
            rec = extract(entry["cve"])
            examined += 1
            if rec["cve_id"] in locked:
                continue
            if not is_complete(rec):
                continue
            shape = (rec["attack_vector"],
                     rec["confidentiality_impact"],
                     rec["integrity_impact"],
                     rec["availability_impact"])
            if shapes[shape] >= MAX_PER_SHAPE:
                continue
            shapes[shape] += 1
            kept.append(rec)
            print(f"  [{len(kept):2}/{POOL_TARGET}] {rec['cve_id']:16} "
                  f"AV:{rec['attack_vector']:16} "
                  f"C:{rec['confidentiality_impact']} "
                  f"I:{rec['integrity_impact']} "
                  f"A:{rec['availability_impact']}  {rec['cwe_id']}")
            if len(kept) >= POOL_TARGET:
                break

        start_index += RESULTS_PER_PAGE
        if start_index >= total:
            print("Reached end of window."); break
        time.sleep(0.5)   # be polite to the API

    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(kept, f, indent=4)

    print(f"\nExamined {examined} CVEs, saved {len(kept)} diverse candidates to {OUTPUT}")
    by_av = defaultdict(int)
    for (av, *_), n in shapes.items():
        by_av[av] += n
    print("Attack-vector spread:", dict(by_av))
    overlap = {r['cve_id'] for r in kept} & locked
    print("Leakage check:", "FAIL" if overlap else "PASS (none in locked 500)")


if __name__ == "__main__":
    main()