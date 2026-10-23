"""Create a clean labelling sheet for an independent annotator (no labels shown)."""
import csv, os

HERE = os.path.dirname(os.path.abspath(__file__))

in_path  = os.path.join(HERE, 'labelling_sheet.csv')
out_path = os.path.join(HERE, 'friend_labelling_sheet.csv')

with open(in_path, encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

with open(out_path, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=['item_id','extracted','ground_truth','cwe_ids','your_label'])
    writer.writeheader()
    for r in rows:
        writer.writerow({
            'item_id':      r['item_id'],
            'extracted':    r['extracted'],
            'ground_truth': r['ground_truth'],
            'cwe_ids':      r['cwe_ids'],
            'your_label':   '',
        })

print(f'Clean sheet written to {out_path}')
