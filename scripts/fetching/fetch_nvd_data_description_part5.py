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
    return {
        "confidentiality_impact": None,
        "integrity_impact": None,
        "availability_impact": None,
    }


def get_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return None


results = []
for entry in cves:
    cve = entry["cve"]
    cia = get_cia_impact(cve)
    results.append({
        "description": get_description(cve),
        "vulnerability_type": get_vulnerability_type(cve),
        "attack_vector": get_attack_vector(cve),
        "confidentiality_impact": cia["confidentiality_impact"],
        "integrity_impact": cia["integrity_impact"],
        "availability_impact": cia["availability_impact"],
        "cve": cve
    })

with open("step5_description.json", "w", encoding="utf-8") as file:
    json.dump(results, file, indent=4)

print(f"Fetched {len(results)} CVEs\n")
for r in results:
    cve_id = r["cve"]["id"]
    date = r["cve"]["published"][:10]
    desc = r["description"] or "MISSING"
    vt = r["vulnerability_type"] or "MISSING"
    av = r["attack_vector"] or "MISSING"
    c = r["confidentiality_impact"] or "MISSING"
    i = r["integrity_impact"] or "MISSING"
    a = r["availability_impact"] or "MISSING"
    print(f"{cve_id} ({date})")
    print(f"  description             = {desc}")
    print(f"  vulnerability_type      = {vt}")
    print(f"  attack_vector           = {av}")
    print(f"  confidentiality_impact  = {c}")
    print(f"  integrity_impact        = {i}")
    print(f"  availability_impact     = {a}")
    print()
