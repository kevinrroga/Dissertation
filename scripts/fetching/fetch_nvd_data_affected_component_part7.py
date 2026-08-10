import os
import json
import random
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

base_params = {
    "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
    "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
}

# NEW: figure out how many CVEs exist in this window in total, so we can
# pick a RANDOM starting point instead of always reading from index 0.
# resultsPerPage=1 here just to read totalResults cheaply — we don't need
# the actual CVE data from this call, only the count.
probe_params = {**base_params, "resultsPerPage": 1}
probe_response = requests.get(url, headers=headers, params=probe_params)
probe_response.raise_for_status()
total_results = probe_response.json()["totalResults"]

results_per_page = 5
max_start_index = max(0, total_results - results_per_page)
random_start_index = random.randint(0, max_start_index)

print(f"{total_results} total CVEs in this 30-day window. "
      f"Picking a random page starting at index {random_start_index}.\n")

# Now the real call, same as part7, but with a random startIndex added.
params = {
    **base_params,
    "resultsPerPage": results_per_page,
    "startIndex": random_start_index,
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


def get_cvss_vector(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0]["cvssData"].get("vectorString")
    return None


def get_affected_components(cve):
    components = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    pair = f"{vendor} {product}"
                    if pair not in components:
                        components.append(pair)

    if components:
        return {"source": "cpe", "components": components}

    for affected_entry in cve.get("affected", []):
        for ad in affected_entry.get("affectedData", []):
            vendor = ad.get("vendor", "")
            product = ad.get("product", "")
            pair = f"{vendor} {product}".strip()
            if pair and pair not in components:
                components.append(pair)

    return {"source": "affected", "components": components}


results = []
for entry in cves:
    cve = entry["cve"]
    cia = get_cia_impact(cve)
    affected = get_affected_components(cve)
    results.append({
        "description": get_description(cve),
        "cvss_vector": get_cvss_vector(cve),
        "vulnerability_type": get_vulnerability_type(cve),
        "attack_vector": get_attack_vector(cve),
        "confidentiality_impact": cia["confidentiality_impact"],
        "integrity_impact": cia["integrity_impact"],
        "availability_impact": cia["availability_impact"],
        "affected_component_source": affected["source"],
        "affected_components": affected["components"],
        "cve": cve
    })

with open("step8_random_sample.json", "w", encoding="utf-8") as file:
    json.dump(results, file, indent=4)

print(f"Fetched {len(results)} CVEs (random page)\n")
for r in results:
    cve_id = r["cve"]["id"]
    date = r["cve"]["published"][:10]
    desc = r["description"] or "MISSING"
    vector = r["cvss_vector"] or "MISSING"
    vt = r["vulnerability_type"] or "MISSING"
    av = r["attack_vector"] or "MISSING"
    c = r["confidentiality_impact"] or "MISSING"
    i = r["integrity_impact"] or "MISSING"
    a = r["availability_impact"] or "MISSING"
    source = r["affected_component_source"]
    components = r["affected_components"] or ["MISSING"]
    print(f"{cve_id} ({date})")
    print(f"  description             = {desc[:100]}...")
    print(f"  cvss_vector             = {vector}")
    print(f"  vulnerability_type      = {vt}")
    print(f"  attack_vector           = {av}")
    print(f"  confidentiality_impact  = {c}")
    print(f"  integrity_impact        = {i}")
    print(f"  availability_impact     = {a}")
    print(f"  affected_components ({source}, {len(components)} total):")
    for comp in components:
        print(f"      - {comp}")
    print()