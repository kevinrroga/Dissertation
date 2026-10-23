"""
Run vuln_type_matcher over the 200-pair sample and compare against the
human labels in labelling_sheet.csv. Report agreement and disagreements.
"""
import csv, json, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'matcher_validator'))
from vuln_type_matcher import classify

sheet_path = os.path.join(HERE, 'labelling_sheet.csv')
json_path  = os.path.join(HERE, 'sample_200.json')

sample = json.load(open(json_path, encoding='utf-8'))
# key in sample_200.json is cve_id__model__condition; build item_id lookup via sheet
rows = list(csv.DictReader(open(sheet_path, encoding='utf-8')))

agree = 0
disagree_rows = []

for row in rows:
    key = f"{row['cve_id']}__{row['model']}__{row['prompt_condition']}"
    d = sample[key]
    matcher_verdict = classify(d['ext'], d['gt'], d['cwes'])
    human_label     = row['your_label'].strip()
    ok = (matcher_verdict == human_label)
    if ok:
        agree += 1
    else:
        disagree_rows.append({
            'item_id': row['item_id'],
            'extracted': d['ext'],
            'ground_truth': ' | '.join(d['gt']),
            'cwe': ' | '.join(d['cwes']),
            'human': human_label,
            'matcher': matcher_verdict,
        })

total = len(rows)
print(f'Agreement: {agree}/{total} = {agree/total*100:.1f}%')
print(f'Disagreements: {len(disagree_rows)}')
print()
print(f'{"item":8} {"extracted":45} {"GT (truncated)":40} {"human":8} {"matcher":8}')
print('-' * 115)
for r in disagree_rows:
    print(f'{r["item_id"]:8} {r["extracted"][:44]:45} {r["ground_truth"][:39]:40} {r["human"]:8} {r["matcher"]:8}')

# save disagree list
out_path = os.path.join(HERE, 'disagreements.json')
with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(disagree_rows, f, indent=2, ensure_ascii=False)
print(f'\nDisagreements saved to {out_path}')
