"""
Annotator 2 labels — second independent pass over the 200-pair sample.
Saved separately from annotator1 (labelling_sheet.csv) so Kappa can be computed.
"""
import csv, os

HERE = os.path.dirname(os.path.abspath(__file__))

LABELS_A2 = {
    'VT-001': 'family',   # Algorithmic Complexity vs Uncontrolled Resource Consumption — related cause
    'VT-002': 'miss',     # Denial of Service vs Out-of-bounds Read — completely different
    'VT-003': 'miss',     # Code Injection vs prototype pollution (CWE-915) — different CWEs
    'VT-004': 'miss',     # User Enumeration vs Observable Response Discrepancy — attack vs mechanism
    'VT-005': 'exact',    # Uncontrolled Recursion == Uncontrolled Recursion
    'VT-006': 'family',   # Denial of Service vs Improper Resource Shutdown — resource shutdown directly causes DoS, same family
    'VT-007': 'family',   # Path Traversal vs Relative Path Traversal — broader parent
    'VT-008': 'miss',     # Policy Bypass vs CWE-280 — vague, different concept
    'VT-009': 'exact',    # Heap-based Buffer Overflow == Heap-based Buffer Overflow
    'VT-010': 'exact',    # Improper Validation of Certificate with Host Mismatch == same
    'VT-011': 'miss',     # Resource Leak vs memory buffer operations — different
    'VT-012': 'family',   # Privilege Escalation vs Improper Privilege Management — attack directly enabled by this weakness
    'VT-013': 'exact',    # Uncontrolled Recursion == same
    'VT-014': 'exact',    # Improper Certificate Validation == same
    'VT-015': 'miss',     # Arbitrary Code Execution vs Untrusted Search Path — impact vs mechanism
    'VT-016': 'exact',    # SQL Injection — alias in parenthetical of CWE-89
    'VT-017': 'exact',    # Session Fixation == same
    'VT-018': 'exact',    # Resource Allocation Without Limits vs CWE-770 — same concept
    'VT-019': 'exact',    # Cross-Site Scripting — alias of CWE-79
    'VT-020': 'miss',     # Insufficient Input Validation vs Uncontrolled Resource Consumption — different
    'VT-021': 'family',   # Stack Overflow vs Out-of-bounds Write — same memory corruption family
    'VT-022': 'exact',    # Improper Authorization vs Incorrect Authorization — both say "authorization", same concept to a non-expert
    'VT-023': 'exact',    # Path Traversal — alias in parenthetical of CWE-22
    'VT-024': 'exact',    # multi-GT includes Improper Authorization (CWE-285) — direct match
    'VT-025': 'miss',     # Path Traversal vs Link Following — different weaknesses
    'VT-026': 'exact',    # Out-of-Bounds Read == Out-of-bounds Read
    'VT-027': 'exact',    # same as VT-022
    'VT-028': 'miss',     # Uncontrolled Resource Consumption vs cryptographic signature — different
    'VT-029': 'exact',    # Server-Side Request Forgery — alias of CWE-918
    'VT-030': 'exact',    # Cross-Site Scripting — alias of CWE-79
    'VT-031': 'family',   # Symlink Race Condition vs CWE-59+367 — covers both concepts
    'VT-032': 'exact',    # NULL Pointer Dereference == same
    'VT-033': 'exact',    # same as VT-022
    'VT-034': 'miss',     # Privilege Escalation vs Uncontrolled Search Path — too indirect
    'VT-035': 'exact',    # Improper Check or Handling of Exceptional Conditions == same
    'VT-036': 'exact',    # same as VT-022
    'VT-037': 'miss',     # Improper Input Validation vs Stack-based Buffer Overflow — generic vs specific
    'VT-038': 'exact',    # Uncontrolled Recursion == same
    'VT-039': 'exact',    # Server-Side Request Forgery — alias of CWE-918
    'VT-040': 'family',   # Insecure Deserialization vs Deserialization of Untrusted Data — related but phrasing differs enough for family
    'VT-041': 'exact',    # multi-GT includes CWE-918 SSRF — exact under any-rule
    'VT-042': 'family',   # Buffer Overflow vs CWE-130 — both under CWE-119 memory family
    'VT-043': 'exact',    # Server-Side Request Forgery — alias of CWE-918
    'VT-044': 'exact',    # same
    'VT-045': 'exact',    # Symlink Following vs multi-GT including CWE-61 — exact under any-rule
    'VT-046': 'exact',    # Cross-Site Scripting — alias of CWE-79
    'VT-047': 'miss',     # Privilege Escalation vs Uncontrolled Search Path — too indirect
    'VT-048': 'miss',     # Denial of Service vs CWE-248+1321 — DoS is impact
    'VT-049': 'exact',    # Integer Overflow == Integer Overflow or Wraparound
    'VT-050': 'exact',    # multi-GT includes CWE-190 — exact under any-rule
    'VT-051': 'family',   # Insecure Deserialization vs multi-GT — same reasoning as VT-040
    'VT-052': 'family',   # Denial of Service vs Improper Resource Shutdown — same reasoning as VT-006
    'VT-053': 'miss',     # Embedded Malicious Code vs Code Injection — different CWEs
    'VT-054': 'family',   # Improper Authorization vs Incorrect Privilege Assignment — same access control family
    'VT-055': 'exact',    # multi-GT includes CWE-918 — exact under any-rule
    'VT-056': 'family',   # PHP Object Injection vs Deserialization of Untrusted Data — specific vs general
    'VT-057': 'exact',    # Missing Authorization == same
    'VT-058': 'miss',     # Resource Exhaustion vs message integrity — different
    'VT-059': 'family',   # Command Injection vs OS Command Injection — parent concept
    'VT-060': 'miss',     # Improper Authorization vs Deserialization — different
    'VT-061': 'family',   # same as VT-052
    'VT-062': 'miss',     # Improper Authorization vs Insufficiently Protected Credentials — different
    'VT-063': 'family',   # Command Injection vs OS Command Injection — parent concept
    'VT-064': 'miss',     # Information Disclosure vs memory leak — different
    'VT-065': 'family',   # Privilege Escalation vs Improper Privilege Management — same as VT-012
    'VT-066': 'exact',    # Cross-Site Scripting — alias of CWE-79
    'VT-067': 'family',   # Environment Variable Injection vs CWE-15 — specific form of external control
    'VT-068': 'miss',     # Improper Authorization vs client-side authentication — different
    'VT-069': 'miss',     # Privilege Escalation vs Uncontrolled Search Path — too indirect
    'VT-070': 'family',   # Improper Link Resolution Before File Access vs CWE-61 — CWE-59 parent
    'VT-071': 'exact',    # Path Traversal — alias of CWE-22
    'VT-072': 'exact',    # Uncontrolled Resource Consumption == same
    'VT-073': 'family',   # same as VT-052
    'VT-074': 'exact',    # Integer Overflow == Integer Overflow or Wraparound
    'VT-075': 'exact',    # Uncontrolled Resource Consumption == same
    'VT-076': 'exact',    # Use-After-Free == Use After Free
    'VT-077': 'family',   # Out-of-bounds Read vs Out-of-bounds Write — same family, wrong direction
    'VT-078': 'miss',     # Information Leak vs memory leak — different
    'VT-079': 'family',   # Path Traversal vs Absolute Path Traversal — parent vs child
    'VT-080': 'family',   # same as VT-052
    'VT-081': 'exact',    # Use-After-Free == Use After Free
    'VT-082': 'miss',     # Improper Input Validation vs Origin Validation Error — different
    'VT-083': 'exact',    # Cross-Site Scripting — alias of CWE-79
    'VT-084': 'exact',    # same
    'VT-085': 'exact',    # Insertion of Sensitive Information into Log File == same
    'VT-086': 'exact',    # Double Free == same
    'VT-087': 'miss',     # Denial of Service vs Missing Release of Resource — less direct
    'VT-088': 'exact',    # Server-Side Template Injection — alias of CWE-1336
    'VT-089': 'exact',    # Improper Authorization vs Missing Authorization — both authorization, non-expert calls exact
    'VT-090': 'exact',    # Use After Free == same
    'VT-091': 'family',   # Buffer Overflow vs Heap-based Buffer Overflow — parent vs child
    'VT-092': 'exact',    # Out-of-bounds Write == same
    'VT-093': 'exact',    # Cross-Site Scripting — alias of CWE-79
    'VT-094': 'family',   # same as VT-052
    'VT-095': 'miss',     # Improper Input Validation vs Infinite Loop — different
    'VT-096': 'exact',    # Improper Check or Handling of Exceptional Conditions == same
    'VT-097': 'exact',    # SQL Injection — alias of CWE-89
    'VT-098': 'miss',     # Authentication Bypass vs Incorrect Authorization — authn vs authz
    'VT-099': 'miss',     # Path Traversal vs link following — different
    'VT-100': 'exact',    # same as VT-022
    'VT-101': 'family',   # Information Disclosure vs Exposure of Sensitive Information — phrasing differs enough for family
    'VT-102': 'family',   # Improper Authorization vs Improper Privilege Management — same access control family
    'VT-103': 'miss',     # Improper TLS Enforcement vs Improper Certificate Validation — different TLS concerns
    'VT-104': 'exact',    # same as VT-089
    'VT-105': 'family',   # Out-of-bounds Read vs CWE-130 — both under CWE-119
    'VT-106': 'exact',    # Cross-Site Scripting — alias of CWE-79
    'VT-107': 'family',   # Buffer Over-read vs Out-of-bounds Read — related but phrasing different enough
    'VT-108': 'exact',    # Integer Overflow == Integer Overflow or Wraparound
    'VT-109': 'family',   # Command Injection vs OS Command Injection — parent concept
    'VT-110': 'miss',     # Information Disclosure vs Missing Authorization — different
    'VT-111': 'exact',    # Improper Restriction of Excessive Authentication Attempts == same
    'VT-112': 'exact',    # Cross-Site Scripting — alias of CWE-79
    'VT-113': 'miss',     # Improper Input Validation vs Out-of-bounds Write — different
    'VT-114': 'exact',    # same as VT-111
    'VT-115': 'family',   # Information Disclosure vs multi-GT — same as VT-101
    'VT-116': 'exact',    # same as VT-089
    'VT-117': 'exact',    # same as VT-022
    'VT-118': 'exact',    # SQL Injection — alias of CWE-89
    'VT-119': 'family',   # Uncontrolled Resource Consumption vs Allocation Without Limits — parent vs child
    'VT-120': 'exact',    # Improper Verification of Cryptographic Signature == same
    'VT-121': 'miss',     # Out-of-bounds Read vs Uncontrolled Recursion — different
    'VT-122': 'exact',    # Cross-Site Scripting — alias of CWE-79
    'VT-123': 'family',   # same as VT-052
    'VT-124': 'exact',    # Buffer Overflow vs multi-GT including Classic Buffer Overflow — near-alias
    'VT-125': 'miss',     # Improper Input Validation vs CWE-939 — different
    'VT-126': 'family',   # Insecure Permissions vs Incorrect Default Permissions — broader informal term
    'VT-127': 'exact',    # same as VT-089
    'VT-128': 'exact',    # Server-Side Request Forgery — alias of CWE-918
    'VT-129': 'exact',    # Heap Buffer Overflow == Heap-based Buffer Overflow
    'VT-130': 'family',   # Buffer Overflow vs Out-of-bounds Write — same memory corruption family
    'VT-131': 'miss',     # Improper Authentication vs Insufficient Session Expiration — different
    'VT-132': 'exact',    # multi-GT includes CWE-77 Command Injection — exact under any-rule
    'VT-133': 'family',   # Improper Input Validation vs Improper Validation of Array Index — parent vs child
    'VT-134': 'exact',    # Prototype Pollution — alias in parenthetical of CWE-1321
    'VT-135': 'family',   # Improper URL Normalization vs CWE-647 — related concept
    'VT-136': 'miss',     # Insufficient Input Validation vs resource allocation — different
    'VT-137': 'miss',     # Arbitrary Code Execution vs Untrusted Search Path — impact vs mechanism
    'VT-138': 'miss',     # Heap Information Disclosure vs memory leak — different
    'VT-139': 'family',   # Improper Link Resolution vs CWE-61 — CWE-59 parent concept
    'VT-140': 'exact',    # Use After Free == same
    'VT-141': 'exact',    # Path Traversal — alias of CWE-22
    'VT-142': 'family',   # Improper Input Validation vs Improper Validation of Specified Type — parent vs child
    'VT-143': 'exact',    # Path Traversal — alias of CWE-22
    'VT-144': 'family',   # Improper Authorization vs Incorrect Permission Assignment — same access control family
    'VT-145': 'miss',     # Code Execution via Malicious Image vs CWE-829 — impact vs mechanism
    'VT-146': 'exact',    # same as VT-022
    'VT-147': 'miss',     # Resource Leak vs memory buffer operations — different
    'VT-148': 'exact',    # Command Injection — alias in parenthetical of CWE-77
    'VT-149': 'miss',     # Improper Input Validation vs permission assignment — different
    'VT-150': 'family',   # Uncontrolled Resource Consumption vs Memory Allocation Excessive Size — parent vs child
    'VT-151': 'exact',    # TOCTOU Race Condition — alias of CWE-367
    'VT-152': 'exact',    # Time-of-check to time-of-use (TOCTOU) — matches CWE-367
    'VT-153': 'exact',    # Improper Certificate Validation == same
    'VT-154': 'exact',    # Out-of-Bounds Read == Out-of-bounds Read
    'VT-155': 'exact',    # Command Injection — alias of CWE-77
    'VT-156': 'family',   # Information Disclosure vs multi-GT — same as VT-101
    'VT-157': 'exact',    # Uncontrolled Resource Consumption == same
    'VT-158': 'miss',     # Improper Input Validation vs Interpretation Conflict — different
    'VT-159': 'exact',    # OS Command Injection — alias of CWE-78
    'VT-160': 'miss',     # Cleartext Storage vs log file insertion — different storage mechanisms
    'VT-161': 'family',   # same as VT-052
    'VT-162': 'miss',     # Code Execution vs CWE-829 — impact vs mechanism
    'VT-163': 'family',   # Improper Authorization vs Incorrect Privilege Assignment — same access control family
    'VT-164': 'exact',    # Cleartext Transmission of Sensitive Information == same
    'VT-165': 'miss',     # Improper Authorization vs Incorrect Default Permissions — different
    'VT-166': 'exact',    # Reflected Cross-Site Scripting — subtype of CWE-79
    'VT-167': 'exact',    # XML External Entity (XXE) Injection — alias of CWE-611
    'VT-168': 'exact',    # multi-GT includes CWE-77 Command Injection — exact under any-rule
    'VT-169': 'miss',     # Improper Authorization vs Authentication Bypass — authz vs authn
    'VT-170': 'miss',     # Improper Input Validation vs type conversion — different
    'VT-171': 'miss',     # Path Traversal vs link following+permissions — different
    'VT-172': 'family',   # Stack Overflow vs Stack-based Buffer Overflow — related but ambiguous
    'VT-173': 'miss',     # Prompt Injection vs template injection — different injection types
    'VT-174': 'family',   # same as VT-052
    'VT-175': 'exact',    # Out-of-bounds Read == same
    'VT-176': 'exact',    # multi-GT includes Improper Authorization (CWE-285) — exact under any-rule
    'VT-177': 'exact',    # multi-GT includes CWE-89 SQL Injection — exact under any-rule
    'VT-178': 'exact',    # Out-of-bounds Write == same
    'VT-179': 'family',   # Improper Authorization vs Incorrect Permission Assignment — same access control family
    'VT-180': 'miss',     # Improper Input Validation vs Out-of-bounds Read — different
    'VT-181': 'exact',    # Command Injection — alias of CWE-77
    'VT-182': 'exact',    # Use-After-Free == Use After Free
    'VT-183': 'exact',    # Out-of-bounds Read == same
    'VT-184': 'family',   # Improper Access Control vs CWE-639 — parent vs child
    'VT-185': 'miss',     # Arbitrary Code Execution vs Untrusted Search Path — impact vs mechanism
    'VT-186': 'exact',    # Path Traversal — alias of CWE-22
    'VT-187': 'exact',    # SSRF — exact under any-rule
    'VT-188': 'exact',    # same as VT-022
    'VT-189': 'exact',    # Regular Expression Denial of Service — alias of CWE-1333
    'VT-190': 'exact',    # Out-of-bounds Read == same
    'VT-191': 'family',   # Authentication Brute Force vs Improper Restriction of Auth Attempts — attack vs weakness
    'VT-192': 'family',   # Improper Authorization vs Incorrect Privilege Assignment — same access control family
    'VT-193': 'family',   # Improper Access Control vs CWE-639 — parent vs child
    'VT-194': 'exact',    # multi-GT includes CWE-190 — exact under any-rule
    'VT-195': 'family',   # Use-After-Free vs Release of Invalid Pointer — both memory safety issues
    'VT-196': 'miss',     # Improper Authorization vs Improper Certificate Validation — different
    'VT-197': 'family',   # Command Injection vs OS Command Injection — parent concept
    'VT-198': 'exact',    # DLL Hijacking — common name for CWE-427
    'VT-199': 'family',   # Buffer Overflow vs Classic Buffer Overflow — near-alias, consistent with sample30 human label
    'VT-200': 'exact',    # LDAP Injection — alias of CWE-90
}

# write to CSV
out_path = os.path.join(HERE, 'annotator2_labelling_sheet.csv')
in_path  = os.path.join(HERE, 'labelling_sheet.csv')

rows = list(__import__('csv').DictReader(open(in_path, encoding='utf-8')))
with open(out_path, 'w', newline='', encoding='utf-8') as f:
    writer = __import__('csv').DictWriter(f, fieldnames=['item_id','extracted','ground_truth','cwe_ids','your_label'])
    writer.writeheader()
    for r in rows:
        writer.writerow({
            'item_id':      r['item_id'],
            'extracted':    r['extracted'],
            'ground_truth': r['ground_truth'],
            'cwe_ids':      r['cwe_ids'],
            'your_label':   LABELS_A2[r['item_id']],
        })

from collections import Counter
c = Counter(LABELS_A2.values())
print(f'Annotator 2 labels written: {len(LABELS_A2)}')
print(f'  exact:   {c["exact"]}')
print(f'  family:  {c["family"]}')
print(f'  partial: {c["partial"]}')
print(f'  miss:    {c["miss"]}')
print(f'Written to {out_path}')
