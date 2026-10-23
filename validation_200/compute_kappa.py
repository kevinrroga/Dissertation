"""Compute Cohen's Kappa between Annotator 1 and Annotator 2."""
import csv, os
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))

a1 = {r['item_id']: r['your_label']
      for r in csv.DictReader(open(os.path.join(HERE, 'labelling_sheet.csv'), encoding='utf-8'))}
a2 = {r['item_id']: r['your_label']
      for r in csv.DictReader(open(os.path.join(HERE, 'annotator2_labelling_sheet.csv'), encoding='utf-8'))}

items = sorted(a1.keys())
LABELS = ['exact', 'family', 'partial', 'miss']

# agreement
agree = sum(1 for i in items if a1[i] == a2[i])
total = len(items)
po = agree / total

# confusion matrix
conf = Counter((a1[i], a2[i]) for i in items)

# expected agreement
a1_counts = Counter(a1[i] for i in items)
a2_counts = Counter(a2[i] for i in items)
pe = sum((a1_counts[l]/total) * (a2_counts[l]/total) for l in LABELS)

kappa = (po - pe) / (1 - pe)

print(f'Annotator 1: exact={a1_counts["exact"]}  family={a1_counts["family"]}  miss={a1_counts["miss"]}  partial={a1_counts["partial"]}')
print(f'Annotator 2: exact={a2_counts["exact"]}  family={a2_counts["family"]}  miss={a2_counts["miss"]}  partial={a2_counts["partial"]}')
print()
print(f'Observed agreement (Po): {agree}/{total} = {po:.3f}')
print(f'Expected agreement (Pe): {pe:.3f}')
print(f"Cohen's Kappa:           {kappa:.3f}")
print()

# interpretation
if kappa >= 0.8:
    interp = 'Almost perfect'
elif kappa >= 0.6:
    interp = 'Substantial'
elif kappa >= 0.4:
    interp = 'Moderate'
elif kappa >= 0.2:
    interp = 'Fair'
else:
    interp = 'Slight'
print(f'Interpretation (Landis & Koch): {interp}')
print()

# disagreements
print('Disagreements:')
print(f'{"item":8} {"extracted":45} {"A1":8} {"A2":8}')
print('-'*75)
for i in items:
    if a1[i] != a2[i]:
        row = next(r for r in csv.DictReader(open(os.path.join(HERE, 'labelling_sheet.csv'), encoding='utf-8')) if r['item_id'] == i)
        print(f'{i:8} {row["extracted"][:44]:45} {a1[i]:8} {a2[i]:8}')
