# data/nvd_steps/

Intermediate outputs from Day 1–2, produced while building the NVD fetch
pipeline one field at a time in [`../../scripts/fetching/`](../../scripts/fetching/README.md).
Each file is the output of the correspondingly-named `fetch_nvd_data_*.py`
script; useful for seeing exactly what each extraction step added, but
superseded by the combined pipeline in `../../scripts/dataset/`.

- **step1_raw_5_cves.json**: Raw NVD API response for 5 CVEs, no field
  extraction (from `fetch_nvd_data_part1.py`).
- **step2_vulnerability_type.json**: Adds the extracted CWE/vulnerability
  type field (`fetch_nvd_data_vulnerabilitytype_part2.py`).
- **step3_attack_vector.json**: Adds the extracted attack vector field
  (`fetch_nvd_data_attackvector_part3.py`).
- **step4_cia_impact.json**: Adds confidentiality/integrity/availability
  impact fields (`fetch_nvd_data_cia_impact_part4.py`).
- **step5_description.json**: Adds the CVE description text
  (`fetch_nvd_data_description_part5.py`).
- **step6_cvss_vector.json**: Adds the full CVSS vector string
  (`fetch_nvd_data_cvssvector_part6.py`).
- **step7_affected_component.json**: Intended output of
  `fetch_nvd_data_affected_component_part7.py` (affected component/CPE
  extraction); currently empty in this checkout.
- **step8_random_sample.json**: A random sample pulled during this stage
  of development, used to sanity-check the fields extracted so far.
- **step_vulnerability_type.json**: An earlier/alternate run of the CWE
  extraction step, storing just `cve_id` / `published` / `vulnerability_type`
  rather than the full CVE record.
