"""
Vulnerability-type matcher — four-way classifier: exact / family / partial / miss.

Implements the locked decision rules:
  - B-upgraded matching: canonical name + parenthetical alias + discriminating-token overlap
  - exact  : model's committed answer names the same specific weakness (alias/phrasing allowed)
  - family : model's committed answer is a correct parent/sibling/named-component within the
             same weakness hierarchy (uses a small dataset-specific parent map)
  - partial: model gave MULTIPLE types (a hedge) and one matches; never a headline hit
  - miss   : wrong / unrelated / null
  - multi-CWE ground truth ("any" rule): match against every assigned CWE, keep strongest outcome
  - Case B (single-CWE GT + multi-type answer): correct fragment present -> partial; else miss

The strength ordering is exact > family > partial > miss.
"""

import re, json

# ---- Small dataset-specific hierarchy map (only clusters that actually collide) ----
# Maps a CWE to the set of *broader/related terms* that count as a FAMILY match for it.
# Terms are normalized (lowercase, hyphens->spaces). Justified by CWEs present in the data.
FAMILY_TERMS = {
    # memory-corruption cluster (all under CWE-119)
    'CWE-121': {'buffer overflow', 'memory corruption'},           # stack-based
    'CWE-122': {'buffer overflow', 'memory corruption'},           # heap-based
    'CWE-120': {'buffer overflow', 'memory corruption'},           # classic
    'CWE-787': {'buffer overflow', 'memory corruption'},           # out-of-bounds write
    'CWE-125': {'buffer overflow', 'memory corruption', 'out of bounds'},  # oob read
    'CWE-680': {'buffer overflow', 'memory corruption'},           # integer-overflow-to-buffer-overflow
    'CWE-119': {'buffer overflow', 'memory corruption'},
    # injection cluster (under CWE-74)
    'CWE-77':  {'injection'},
    'CWE-78':  {'injection', 'command injection'},
    'CWE-89':  {'injection'},
    'CWE-79':  {'injection'},
    'CWE-94':  {'injection'},
    'CWE-1236':{'injection'},
    # credential cluster
    'CWE-798': {'hardcoded credentials', 'hard coded credentials', 'hardcoded key',
                'hard coded key', 'hardcoded cryptographic key', 'credential'},
}

# Compound terms whose internal slash is part of ONE concept, not a hedge between two.
COMPOUND_TERMS = {
    'csv/formula injection', 'read/write', 'request/response',
    'concurrency/locking defect', 'input/output',
}

# Specificity qualifiers: when GT carries these extra tokens over the fragment,
# the fragment is the correct BROADER term -> family, not exact.
SPECIFICITY_TOKENS = {'stack', 'heap', 'classic', 'integer', 'unbounded'}

# Canonical short names per CWE, harvested where the MITRE name hides the real term
# in a parenthetical alias. Used to strengthen EXACT detection.
CANON_ALIAS = {
    'CWE-77':  ['command injection'],
    'CWE-78':  ['os command injection', 'command injection'],
    'CWE-120': ['classic buffer overflow', 'buffer overflow'],
    'CWE-918': ['server-side request forgery', 'ssrf'],
    'CWE-1236':['csv injection', 'formula injection'],
    'CWE-416': ['use after free'],
}

STOP = {'of','the','in','a','an','and','or','to','for','without','used','improper',
        'by','with','into','on','elements','special','function','critical'}

def norm(s):
    if not s: return ''
    s = s.lower().replace('-', ' ')
    s = re.sub(r"[()'\",;:]", ' ', s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def content_tokens(s):
    return set(norm(s).split()) - STOP

def split_multi(ext):
    """Split a model answer into fragments IF it is a genuine multi-type hedge.
       A slash inside a known COMPOUND term (e.g. 'CSV/Formula Injection') is one
       concept, not a hedge, so such answers are NOT split."""
    if norm(ext).replace(' ', '') in {c.replace(' ', '').replace('/', '') for c in COMPOUND_TERMS} \
       or ext.strip().lower() in COMPOUND_TERMS:
        return [ext.strip()]
    # also catch compound terms embedded exactly
    low = ext.strip().lower()
    for c in COMPOUND_TERMS:
        if low == c:
            return [ext.strip()]
    parts = re.split(r'\s*/\s*|\s*;\s*|\s+and\s+', ext, flags=re.I)
    return [p.strip() for p in parts if p.strip()]

def single_match(frag, gt_name, cwe):
    """Match ONE fragment against ONE ground-truth (name, cwe). Returns 'exact'|'family'|'miss'."""
    f = norm(frag)
    g = norm(gt_name)
    ftok, gtok = content_tokens(frag), content_tokens(gt_name)

    # EXACT: alias hit, or fragment's content tokens are a subset/superset with strong overlap
    aliases = CANON_ALIAS.get(cwe, [])
    if any(norm(a) == f or norm(a) in f or f in norm(a) for a in aliases):
        return 'exact'
    if ftok and gtok:
        # GT strictly broader-specified than fragment: the extra GT tokens are
        # specificity qualifiers -> fragment is correct-but-broader -> FAMILY.
        if ftok < gtok:
            extra = gtok - ftok
            if extra & SPECIFICITY_TOKENS:
                return 'family'
            return 'exact'          # extra tokens are just filler, e.g. "Missing Authentication" vs "...for Critical Function"
        # fragment superset of GT, or exactly equal -> exact
        if gtok <= ftok:
            return 'exact'
        overlap = ftok & gtok
        # require the DISCRIMINATING token(s) shared, not just filler
        if overlap and len(overlap) >= min(len(ftok), len(gtok)):
            return 'exact'

    # FAMILY: fragment is a known broader/related term for this CWE
    fam = FAMILY_TERMS.get(cwe, set())
    if any(term == f or term in f for term in fam):
        return 'family'

    return 'miss'

RANK = {'exact': 3, 'family': 2, 'partial': 1, 'miss': 0}

def classify(ext, gt_names, cwes):
    """Full four-way classification for one model answer vs (possibly multi) ground truth."""
    if not ext or not isinstance(ext, str):
        return 'miss'
    if isinstance(gt_names, str):
        gt_names = [gt_names]

    fragments = split_multi(ext)
    is_hedge = len(fragments) > 1

    # best single-fragment outcome across all GT CWEs
    best = 'miss'
    for frag in fragments:
        for name, cwe in zip(gt_names, cwes):
            r = single_match(frag, name, cwe)
            if RANK[r] > RANK[best]:
                best = r

    multi_cwe = len(cwes) > 1

    if not is_hedge:
        # committed single answer -> exact/family/miss as found
        return best

    # hedged (multi-type answer)
    if multi_cwe:
        # Case A: matching a real set against a real set is legitimate -> keep best (exact/family)
        return best
    else:
        # Case B: single-CWE GT + hedge. A correct fragment present -> partial (not a headline hit).
        if best in ('exact', 'family'):
            return 'partial'
        return 'miss'


# ---------------- Validation against the 30 hand-labelled pairs ----------------
if __name__ == '__main__':
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    sample = json.load(open(os.path.join(here, 'sample30.json')))

    # Your locked human labels
    HUMAN = {
        'CVE-2026-49198':'exact','CVE-2026-46579':'exact','CVE-2026-42965':'exact','CVE-2026-49195':'exact',
        'CVE-2026-46242':'exact','CVE-2026-49196':'exact','CVE-2025-41265':'exact','CVE-2026-42267':'exact',
        'CVE-2026-49014':'family','CVE-2018-25426':'exact','CVE-2026-43078':'family','CVE-2026-8376':'family',
        'CVE-2025-41266':'exact','CVE-2026-49197':'miss','CVE-2026-39831':'miss','CVE-2026-43617':'miss',
        'CVE-2026-4273':'miss','CVE-2026-49201':'family','CVE-2026-45252':'partial','CVE-2026-45321':'miss',
        'CVE-2026-42217':'partial','CVE-2026-7258':'partial','CVE-2026-42002':'miss','CVE-2026-43870':'exact',
        'CVE-2026-48840':'miss','CVE-2018-25412':'miss','CVE-2026-48210':'miss','CVE-2026-8922':'miss',
        'CVE-2026-6334':'miss','CVE-2026-48686':'family',
    }

    order = list(HUMAN.keys())
    agree = 0
    rows = []
    for cid in order:
        d = sample[cid]
        pred = classify(d['ext'], d['gt'], d['cwes'])
        human = HUMAN[cid]
        ok = (pred == human)
        agree += ok
        rows.append((cid, d['ext'][:40], human, pred, '' if ok else '  <-- DISAGREE'))

    print(f'{"CVE":16} {"extracted":42} {"human":8} {"matcher":8}')
    print('-'*90)
    for cid, ext, human, pred, flag in rows:
        print(f'{cid:16} {ext:42} {human:8} {pred:8}{flag}')
    print('-'*90)
    print(f'Agreement: {agree}/30 = {agree/30*100:.1f}%')