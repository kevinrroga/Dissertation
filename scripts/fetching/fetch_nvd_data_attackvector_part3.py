import os
import json
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("NVD_API_KEY")

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

headers = {
    "apiKey": API_KEY
}

end_date = datetime.utcnow()
start_date = end_date - timedelta(days=30)

params = {
    "resultsPerPage": 5,
    "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
    "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
}

response = requests.get(url, headers=headers, params=params)

if response.status_code != 200:
    print("Error:", response.status_code)
    print(response.text)
    exit()

data = response.json()
cves = data["vulnerabilities"]


def get_vulnerability_type(cve):
    invalid_values = {"NVD-CWE-Other", "NVD-CWE-noinfo"}
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            if d.get("lang") == "en" and d.get("value") not in invalid_values:
                return d["value"]
    return None


def get_attack_vector(cve):
    metrics = cve.get("metrics", {})

    # Prefer CVSS v3.1, then v3.0, then fall back to v2
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0]["cvssData"].get("attackVector")

    entries = metrics.get("cvssMetricV2", [])
    if entries:
        return entries[0]["cvssData"].get("accessVector")

    return None


results = []
for entry in cves:
    cve = entry["cve"]
    results.append({
        "vulnerability_type": get_vulnerability_type(cve),
        "attack_vector": get_attack_vector(cve),
        "cve": cve
    })

with open("step3_attack_vector.json", "w", encoding="utf-8") as file:
    json.dump(results, file, indent=4)

print(f"Fetched {len(results)} CVEs\n")
for r in results:
    vt = r["vulnerability_type"] or "MISSING"
    av = r["attack_vector"] or "MISSING"
    print(f"{r['cve']['id']} ({r['cve']['published'][:10]}): vulnerability_type = {vt} | attack_vector = {av}")
