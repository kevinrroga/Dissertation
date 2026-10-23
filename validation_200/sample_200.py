"""
Sample 200 rows from merging_results.json for manual validation of the
vulnerability-type matcher.

Rules:
  - Only rows with a non-null extracted vulnerability_type.
  - Exclude CVE IDs already in the sample30 validation set.
  - Stratified by model (3) x prompt_condition (2) = 6 cells,
    ~33-34 rows per cell, so every model/condition is represented.
  - Random seed fixed for reproducibility.

Output: validation_200/labelling_sheet.csv  (you fill in the 'your_label' column)
        validation_200/sample_200.json       (machine-readable, used by the scorer)
"""

import json, csv, random, os

SEED = 42
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ── load data ────────────────────────────────────────────────────────────────
results = json.load(open(os.path.join(ROOT, 'ultimate_dataset', 'merging_results.json'), encoding='utf-8'))
sample30 = json.load(open(os.path.join(ROOT, 'matcher_validator', 'sample30.json'), encoding='utf-8'))

excluded_cves = set(sample30.keys())

# ── filter ───────────────────────────────────────────────────────────────────
eligible = [
    r for r in results
    if r.get('extracted', {}).get('vulnerability_type')
    and r['cve_id'] not in excluded_cves
    and all(v is not None for v in (r['ground_truth'].get('vulnerability_type') or []))
    and r['ground_truth'].get('vulnerability_type')
]

# ── stratified sample ────────────────────────────────────────────────────────
from collections import defaultdict
cells = defaultdict(list)
for r in eligible:
    key = (r['model'], r['prompt_condition'])
    cells[key].append(r)

rng = random.Random(SEED)
per_cell = 200 // 6          # 33
remainder = 200 - per_cell * 6  # 2 extra, assigned to first cells

sampled = []
for i, (key, rows) in enumerate(sorted(cells.items())):
    n = per_cell + (1 if i < remainder else 0)
    sampled.extend(rng.sample(rows, n))

rng.shuffle(sampled)

# ── write CSV ─────────────────────────────────────────────────────────────────
csv_path = os.path.join(HERE, 'labelling_sheet.csv')
with open(csv_path, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['item_id', 'cve_id', 'model', 'prompt_condition',
                     'extracted', 'ground_truth', 'cwe_ids', 'your_label'])
    for i, r in enumerate(sampled, 1):
        gt_names = r['ground_truth']['vulnerability_type']
        cwe_ids  = r['ground_truth'].get('cwe_ids', [])
        writer.writerow([
            f'VT-{i:03d}',
            r['cve_id'],
            r['model'],
            r['prompt_condition'],
            r['extracted']['vulnerability_type'],
            ' | '.join(gt_names),
            ' | '.join(cwe_ids),
            '',   # your_label — fill this in
        ])

# ── write JSON (for the scorer) ───────────────────────────────────────────────
json_path = os.path.join(HERE, 'sample_200.json')
out = {}
for r in sampled:
    out[r['cve_id'] + '__' + r['model'] + '__' + r['prompt_condition']] = {
        'cve_id': r['cve_id'],
        'model': r['model'],
        'prompt_condition': r['prompt_condition'],
        'ext': r['extracted']['vulnerability_type'],
        'gt': r['ground_truth']['vulnerability_type'],
        'cwes': r['ground_truth'].get('cwe_ids', []),
    }
with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(out, f, indent=2, ensure_ascii=False)

print(f'Sampled {len(sampled)} rows.')
print(f'CSV  -> {csv_path}')
print(f'JSON -> {json_path}')
print()
print('Cell breakdown:')
from collections import Counter
c = Counter((r['model'], r['prompt_condition']) for r in sampled)
for k, n in sorted(c.items()):
    print(f'  {k[0]:25} {k[1]:12} {n}')
