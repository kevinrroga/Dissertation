# scripts/fetching/

Day 1–2: incremental exploration of the NVD API 2.0, one field at a time,
before it all gets combined into a single fetch pipeline. Each
`fetch_nvd_data_*_partN.py` script is a standalone experiment for extracting
one specific piece of data from a CVE record; their outputs are the
`data/nvd_steps/stepN_*.json` files.

- **fetch_nvd_data_part1.py**: The starting point: fetches 5 random CVEs
  from the NVD API and dumps the raw response, no filtering or field
  extraction yet.
- **fetch_nvd_data_vulnerabilitytype_part2.py**: Adds a recent-CVEs date
  window (last 30 days) and extracts the CWE/vulnerability type field.
- **fetch_nvd_data_attackvector_part3.py**: Extracts the CVSS attack
  vector field.
- **fetch_nvd_data_cia_impact_part4.py**: Extracts confidentiality /
  integrity / availability impact fields.
- **fetch_nvd_data_description_part5.py**: Extracts the CVE description
  text.
- **fetch_nvd_data_cvssvector_part6.py**: Extracts the full CVSS vector
  string.
- **fetch_nvd_data_affected_component_part7.py**: Extracts affected
  component/CPE data.
- **fetch_nvd_data_cpes.py**: A pure inspection tool (not part of the
  build pipeline): pulls a small batch of CVEs and prints their raw CPE
  match data so the ground-truth shape could be seen before writing
  matching logic against it.
- **fetch_correct_final_script.py**: Day 1 deliverable: blends
  part1–part7 into one script, and adds the one genuinely new piece of
  logic: a completeness filter + pagination loop that keeps pulling pages
  until it has 5 CVEs where *all four* required fields are populated
  (rather than accepting whatever the first page returns, gaps included).
- **final_script.py** (`match_affected_component.py`): Day 2 deliverable,
  locked 22 June: defines how an LLM's free-text "affected component"
  answer is scored against the structured NVD CPE ground truth, using
  normalized token overlap with fuzzy tolerance. Documents why embedding
  similarity and manual-only judgment were rejected as the primary scoring
  method.

These scripts are historical/exploratory; the actual 500-CVE dataset build
lives in [`../dataset/`](../dataset/README.md).
