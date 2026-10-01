# LLM-Assisted Triage of Vulnerability Reports

Code, data and results for my MSc dissertation: **LLM-Assisted Triage of Vulnerability Reports: A Comparative Evaluation of Attribute Extraction from CVE Descriptions Across Large Language Models and Prompting Strategies**.

The project tests how well three large language models pull structured information out of free-text CVE descriptions. Each model extracts four things, and each is scored against the official NVD record:

| Entity | Ground truth |
|---|---|
| Vulnerability type | CWE ID(s) in the NVD record |
| Attack vector | `AV:` component of the CVSS v3.1 vector |
| CIA impact | `C:`, `I:`, `A:` components of the CVSS v3.1 vector |
| Affected component | CPE entries in the NVD record |

**Design:** 500 CVEs x 3 models x 2 prompting conditions (zero-shot, few-shot) = 3,000 responses.
**Models:** `gpt-5.5`, `claude-sonnet-4.6`, `deepseek-v4-pro`.
**Dissertation:** [`docs/[FILENAME].pdf`](docs/[FILENAME].pdf)

---

## Start here: two ways to use this repo

**Path A: rerun the scoring (free, about a minute, recommended).**
All 3,000 model responses are already saved in `ultimate_dataset/merging_results.json`, matched to ground truth. You can rescore them and reproduce the dissertation's numbers without any API key. Every scoring script was rerun from a clean copy of this repo before publishing, and all of them completed without errors.

**Path B: rerun the experiment (costs money, will not match exactly).**
Rebuild the dataset from NVD and call the three model APIs again. Model outputs are not deterministic and model versions get retired, so new numbers will drift from mine. This path documents how the data was produced. It is not a promise of identical results.

---

## Setup

Python 3.10 or newer (tested on 3.12).

```bash
git clone https://github.com/kevinrroga/Dissertation.git
cd Dissertation

python -m venv venv
# Windows:      venv\Scripts\activate
# macOS/Linux:  source venv/bin/activate

pip install -r requirements.txt
```

Path A only needs `statsmodels` (for the McNemar tests). Everything else in `requirements.txt` is for Path B.

---

## Path A: reproduce the results

**Run every script from inside its own folder.** They find their inputs with relative paths such as `../ultimate_dataset/merging_results.json`, so running them from the repo root fails with "file not found".

Each scoring folder follows the same order: verify the data, score it, then run the extra analyses.

### Attack vector

```bash
cd scoring_for_attack_vector
python verify_attack_vector.py        # data integrity + label set
python score_attack_vector.py         # main scores
python bootstrap_attack_vector.py     # 95% confidence intervals
python mcnemar.py                     # paired significance tests
python decline_in_attackvector.py     # which CVEs models declined to answer
```

### CIA impact

```bash
cd scoring_for_CIA
python cia_verify.py
python cia_scorer.py                  # writes outputs/*.csv (other scripts read outputs/cia_long.csv)
python bootstrap_for_CIA.py
python mcnemar_for_CIA.py
python cia_decline.py
```

Run `cia_scorer.py` before the bootstrap and McNemar scripts. They read its output.

### Affected component

```bash
cd scoring_for_affected_component
python score_affected_component.py    # writes outputs/*.csv and outputs/affected_component_summary.txt
python bootstrap_affected_component.py
python mcnemar_affected_component.py
```

### Vulnerability type

```bash
cd scoring_for_vuln_type
python score_pillar.py
python bootstrap_vuln_type.py
python mcnemar_vuln_type.py
python declines_vuln_type.py
python sensitivity_alias_provenance.py   # rescores with standards-sourced aliases only (see Known limitations)
```

This folder is self-contained. `score_pillar.py` reads three files sitting next to it, with names hardcoded, so do not rename them:

- `merging_results.json`
- `cwe_aliases_v3_strict_reviewed.json` (maps model wording to CWE IDs)
- `cwe_master_vocabulary_pillar_grouped.json` (CWE names and CWE-1000 pillars)

It writes `vulnerability_type_pillar_scored_details.json`, `..._summary.json` and `..._summary.csv`. The bootstrap, McNemar and declines scripts read the `scored_details` file, so run `score_pillar.py` first.

> **Note:** the docstrings at the top of a few scripts give slightly different filenames from the real ones (for example `mcnemar.py` says `mcnemar_attack_vector.py`). Use the filenames in this README.

---

## How scoring works

**Attack vector and CIA impact.** Each prediction gets one outcome: Correct, Incorrect, Unmapped (value could not be mapped to a valid label), Declined (model gave no answer), or Malformed. Declines count as wrong for accuracy and are analysed separately. Reports include per-class precision, recall and F1.

**Vulnerability type.** A prediction is correct only if it resolves to the exact ground-truth CWE. Wrong answers are then sorted to show *how* they were wrong: `same_pillar_wrong_cwe`, `different_pillar`, `consequence_not_mechanism` (the model described the impact instead of the weakness), or `unmapped_or_absent`. These categories explain errors. They do not change accuracy. Matching decisions are documented in [`day18_vulnerability_type_matching_decisions.md`](day18_vulnerability_type_matching_decisions.md) and checked against a hand-labelled sample in [`vuln_type_validation_sample_30.md`](vuln_type_validation_sample_30.md).

**Affected component.** Two layers: a token-overlap match against any ground-truth component, then a vendor-name fallback reported as "Partial". Partial counts as a miss in the headline F1. Precision is 1.0 by construction, so recall is the informative number.

**Statistics.** 95% bootstrap confidence intervals (5,000 CVE-level resamples, seed 42) and paired McNemar tests comparing models and prompting conditions.

---

## Check your run

After running the scripts above, these should match.

**Vulnerability type** (`scoring_for_vuln_type/vulnerability_type_pillar_summary.csv`):

| Model | Zero-shot accuracy | Few-shot accuracy |
|---|---|---|
| claude-sonnet-4.6 | 0.400 (200/500) | 0.434 (217/500) |
| deepseek-v4-pro | 0.410 (205/500) | 0.434 (217/500) |
| gpt-5.5 | 0.460 (230/500) | 0.482 (241/500) |

**Attack vector**, claude-sonnet-4.6: 88.6% zero-shot (443/500), 88.2% few-shot (441/500).

**Affected component**, binary F1 for claude-sonnet-4.6: 0.708 zero-shot, 0.701 few-shot.

If yours differ, the usual cause is running a script from the wrong folder or editing an input file.

---

## Repository map

```
.
├── README.md
├── requirements.txt
├── .env.example                     # names of the API keys needed for Path B
├── docs/                            # the dissertation PDF
│
├── ultimate_dataset/                # THE canonical inputs for all scoring
│   ├── dataset_v1_locked_24jun_with_cwe_names.json   # frozen 500-CVE dataset + ground truth
│   └── merging_results.json                          # 3,000 model responses + ground truth
│
├── scoring_for_attack_vector/       # scorer, bootstrap, McNemar, declines, verify + outputs
├── scoring_for_CIA/                 # same, outputs in outputs/
├── scoring_for_affected_component/  # same, outputs in outputs/
├── scoring_for_vuln_type/           # same; also holds the alias + vocabulary files
│
├── scripts/                         # Path B, stage 1: building the dataset from NVD
│   ├── fetching/                    #   field-by-field NVD fetch scripts, merged into final_script.py
│   └── dataset/                     #   scaling to the locked 500-CVE set, CWE names
├── building_the_real_dataset.py     # dataset build iterations (see "Dataset history")
├── dataset_walking_backwards.py
├── dataset_with_rejected_filter_applied.py
├── fix_affected_component.py        # CPE parsing fix
├── script_that_links_cwe_to_names/  # attaches CWE names to the locked dataset
│
├── initial_tests/                   # Day 5: one-off API connectivity checks
├── zero_shot/                       # zero-shot runner (patched version, see provenance note)
├── few_shot/                        # few-shot runner, prompt, and the 3 example CVEs
├── real_project_final_notouch/      # the runner versions that produced the stored results
├── comparison_prompts/              # side test: original vs CIA-balanced prompt on 50 CVEs
├── merging_few_0_shot/              # merge script + vulnerability-type label inventories
├── matcher_validator/               # vulnerability-type matcher + its 30-pair validation
│
├── data/                            # intermediate data: NVD steps, datasets, prompts, raw results
├── reports/                         # run logs and verification reports
└── *.md                             # decision logs: Day15_Summary, session_summary, day18_*, ...
```

`scoring/` is an older, superseded vulnerability-type scorer (the "layered" version using author-defined categories). **Use `scoring_for_vuln_type/` instead.**

---

## Path B: rerun the experiment

### 1. API keys

Copy `.env.example` to `.env` and fill in your own keys. `.env` is git-ignored.

### 2. Build the dataset

The scripts in `scripts/fetching/` and `scripts/dataset/` pull CVEs from NVD API 2.0. The dataset used in the dissertation is already frozen in `ultimate_dataset/`. Rerunning the fetch later returns a different set of CVEs, so use the frozen file for any comparison.

**Inclusion criteria:** English description, complete CVSS v3.1 vector, a specific CWE (not `NVD-CWE-noinfo` or `NVD-CWE-Other`), and a CPE entry naming the affected product; rejected CVEs excluded. **Date range:** collected in May 2026 by working backwards from 31 May 2026, at most 20 records per publication date, covering every day from 1 to 31 May 2026. **Size:** 500 CVEs.

### 3. Run the models

```bash
cd zero_shot && python zero_shot_final.py
cd few_shot  && python few_shot.py
```

Each script calls all three models for all 500 CVEs, checkpoints as it goes, and resumes if interrupted. The zero-shot prompt is defined inside `zero_shot_final.py`. The few-shot prompt is `few_shot/few_shot_prompt.txt`, built around three worked examples chosen for diversity and taken from *outside* the 500-CVE evaluation set. `few_shot.py` refuses to run if the examples in the prompt and the declared example IDs ever disagree, which guards against leakage.

### 4. Merge

`merging_few_0_shot/merging_script.py` joins zero-shot results, few-shot results and ground truth into one row per (CVE, model, condition). See the provenance note below before relying on this step.

---

## Provenance of the stored results (please read)

<!-- CONFIRM BEFORE PUBLISHING: check that the paragraph below matches what you actually ran. -->

The stored results were produced by the runner scripts preserved in `real_project_final_notouch/`. The versions in `zero_shot/` and `few_shot/` are later patched copies:

- The original zero-shot run hit an Anthropic credit-exhaustion error partway through, which left 40 stale duplicate rows for `claude-sonnet-4.6` (540 rows for 500 CVEs). They were removed by a cleanup script before merging. The patched `zero_shot_final.py` fixes the resume logic so retries overwrite instead of duplicating.
- The original few-shot run wrote JSONL (`few_shot/results_fewshot-new_file.jsonl`, with raw responses). A first attempt had many failed `claude-sonnet-4.6` rows, so Claude's few-shot calls were rerun; the earlier attempt is kept as `few_shot/results_fewshot-new_file.jsonl.bak-20260709-155627`. The JSON version used for merging is `few_shot/results_fewshot_v1_with_time.json`.
- Raw responses for every output are kept: `zero_shot/output_of_zero-shot.json` and the few-shot files above. Their parsed fields were checked against `merging_results.json` and match for all 3,000 rows.
- Two small helper steps between the raw runner output and `merging_results.json` (cleaning the zero-shot file, converting the few-shot JSONL to JSON) were run as one-off scripts that are **not included in this repository**, and `merging_script.py` expects intermediate `*_tidy.json` files that are not included. The results of those steps are present and consistent, but the scripts are not.

The practical result: **the scoring (Path A) is fully reproducible from the saved data. The merge step is verifiable (raw outputs match the merged file) but cannot be rerun from this repository alone.** `merging_results.json` is the authoritative record of what the models returned.

---

## Known limitations

- **Pillar assignments.** The CWE-1000 pillar for each CWE was assigned from the MITRE Research Concepts hierarchy. [UPDATE: state whether you have now verified these against cwe.mitre.org and how many you checked.]
- **Alias dictionary.** `cwe_aliases_v3_strict_reviewed.json` has 297 aliases: 142 official CWE names, 85 MITRE alternate terms and 70 author-added. The author-added ones were curated while reviewing unresolved model wording, in revisions v4 and v5 that were checked against ground-truth consistency, so they do not all predate the model outputs. The file's own `provenance_note` and `revision_summary` say so. Vulnerability-type scores should be read with that in mind: `sensitivity_alias_provenance.py` rescores with the 70 author-added aliases removed. Strict accuracy falls from 40.0 to 48.2% to 24.0 to 26.8%, because those aliases resolve 695 of the 3,000 predictions and account for 533 of the 1,310 correct answers. The standards-only figure is a lower bound, since ordinary phrasings that are not in the official names end up unmapped. The full-dictionary figure is the upper end of the range. Under standards-only aliases the three models are no longer clearly separated.
- **Affected component has no dedicated NVD field.** The CPE ground truth is imperfect. Models often name a sub-component or feature instead of the registered product name, which scores as "No Match" even when the answer is reasonable.
- **Declines.** Some models decline to answer for some CVEs (GPT-5.5 most often on CIA fields). These count as wrong, and their effect is analysed in the `declines` outputs.
- **Non-determinism.** Rerunning Path B will not reproduce the stored model outputs.
- **Some committed output files are slightly older than their scripts.** For example, the `declines_*_results.json` files in the attack vector and CIA folders lack some CVE-ID lists that the current scripts write. The headline numbers are unaffected. Rerunning the scripts regenerates them.

---

## Dataset history

`building_the_real_dataset.py`, `dataset_walking_backwards.py` and `dataset_with_rejected_filter_applied.py` are successive iterations of the dataset build, kept for the record. The frozen output is `ultimate_dataset/dataset_v1_locked_24jun_with_cwe_names.json`. `scripts/dataset/dataset_with_cwe_names.json` is an earlier refetch that drifted from the locked set and **should not be used**.

---

## Data sources

- CVE, CVSS and CPE data: NVD API 2.0, https://nvd.nist.gov/developers/vulnerabilities
- CWE names and hierarchy: MITRE CWE, https://cwe.mitre.org

## Citation

```
[YOUR NAME]. ([YEAR]). [DISSERTATION TITLE]. MSc dissertation, [UNIVERSITY].
```

## License

[CHOOSE, e.g. MIT for the code.] See `LICENSE`.

## Contact

GitHub: [kevinrroga](https://github.com/kevinrroga)
