# This script fetches 5 CVEs from the NVD API and saves them to a JSON file.
#The CVEs are random and are fetched with all their details from the NVD.

import os
import json
import requests
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("NVD_API_KEY")

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

headers = {
    "apiKey": API_KEY
}

params = {
    "resultsPerPage": 5
}

response = requests.get(url, headers=headers, params=params)

if response.status_code != 200:
    print("Error:", response.status_code)
    print(response.text)
    exit()

data = response.json()

cves = data["vulnerabilities"]

with open("step1_raw_5_cves.json", "w", encoding="utf-8") as file:
    json.dump(cves, file, indent=4)

print("Saved 5 CVEs to step1_raw_5_cves.json")