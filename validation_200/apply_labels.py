"""Write the 200 human labels into labelling_sheet.csv."""
import csv, os

HERE = os.path.dirname(os.path.abspath(__file__))

LABELS = {
    'VT-001': 'family',   # "Algorithmic Complexity" vs "Uncontrolled Resource Consumption" — CWE-407 is child of CWE-400; related cause/effect
    'VT-002': 'miss',     # "Denial of Service" vs "Out-of-bounds Read" — DoS is impact, not weakness type
    'VT-003': 'miss',     # "Code Injection" vs "Improperly Controlled Modification of Dynamically-Determined Object Attributes (CWE-915)" — prototype pollution, different CWE
    'VT-004': 'miss',     # "User Enumeration" vs "Observable Response Discrepancy" — model named the attack, NVD named the enabling mechanism
    'VT-005': 'exact',    # "Uncontrolled Recursion" == "Uncontrolled Recursion"
    'VT-006': 'miss',     # "Denial of Service" vs "Improper Resource Shutdown or Release" — DoS is impact
    'VT-007': 'family',   # "Path Traversal" vs "Relative Path Traversal (CWE-23)" — broader parent vs specific child
    'VT-008': 'miss',     # "Policy Bypass" vs "Improper Handling of Insufficient Permissions or Privileges (CWE-280)" — vague term, different concept
    'VT-009': 'exact',    # "Heap-based Buffer Overflow" == "Heap-based Buffer Overflow"
    'VT-010': 'exact',    # "Improper Validation of Certificate with Host Mismatch" == same (truncated in display)
    'VT-011': 'miss',     # "Resource Leak" vs "Improper Restriction of Operations within Bounds of Memory Buffer (CWE-119)" — different concept
    'VT-012': 'miss',     # "Privilege Escalation" vs "Improper Privilege Management" — model named attack/impact, NVD named the weakness
    'VT-013': 'exact',    # "Uncontrolled Recursion" == "Uncontrolled Recursion"
    'VT-014': 'exact',    # "Improper Certificate Validation" == "Improper Certificate Validation"
    'VT-015': 'miss',     # "Arbitrary Code Execution" vs "Untrusted Search Path (CWE-426)" — ACE is impact
    'VT-016': 'exact',    # "SQL Injection" — alias in parenthetical of CWE-89
    'VT-017': 'exact',    # "Session Fixation" == "Session Fixation"
    'VT-018': 'exact',    # "Resource Allocation Without Limits" vs CWE-770 "Allocation of Resources Without Limits or Throttling" — same concept
    'VT-019': 'exact',    # "Cross-Site Scripting" — alias in parenthetical of CWE-79
    'VT-020': 'miss',     # "Insufficient Input Validation" vs "Uncontrolled Resource Consumption" — different concepts
    'VT-021': 'family',   # "Stack Overflow" vs "Out-of-bounds Write (CWE-787)" — both memory corruption under CWE-119
    'VT-022': 'family',   # "Improper Authorization" vs "Incorrect Authorization (CWE-863)" — CWE-285 is parent of CWE-863
    'VT-023': 'exact',    # "Path Traversal" — alias in parenthetical of CWE-22
    'VT-024': 'exact',    # multi-GT includes "Improper Authorization (CWE-285)" — direct match under any-rule
    'VT-025': 'miss',     # "Path Traversal" vs "Link Following (CWE-59)" — symlink following ≠ path traversal
    'VT-026': 'exact',    # "Out-of-Bounds Read" == "Out-of-bounds Read" (case only)
    'VT-027': 'family',   # same as VT-022
    'VT-028': 'miss',     # "Uncontrolled Resource Consumption" vs "Improper Verification of Cryptographic Signature" — different
    'VT-029': 'exact',    # "Server-Side Request Forgery" — alias/full name of CWE-918
    'VT-030': 'exact',    # "Cross-Site Scripting" — alias in parenthetical of CWE-79
    'VT-031': 'family',   # "Symlink Race Condition" vs CWE-59+CWE-367 — covers both concepts but broader than either specific CWE
    'VT-032': 'exact',    # "NULL Pointer Dereference" == "NULL Pointer Dereference"
    'VT-033': 'family',   # same as VT-022
    'VT-034': 'miss',     # "Privilege Escalation" vs "Uncontrolled Search Path Element (CWE-427)" — impact vs mechanism
    'VT-035': 'exact',    # "Improper Check or Handling of Exceptional Conditions" == same (truncated display)
    'VT-036': 'family',   # same as VT-022
    'VT-037': 'miss',     # "Improper Input Validation" vs "Stack-based Buffer Overflow" — generic vs specific memory corruption
    'VT-038': 'exact',    # "Uncontrolled Recursion" == "Uncontrolled Recursion"
    'VT-039': 'exact',    # "Server-Side Request Forgery" — alias of CWE-918
    'VT-040': 'exact',    # "Insecure Deserialization" — common alias for CWE-502
    'VT-041': 'exact',    # multi-GT: against CWE-918 "SSRF" — exact under any-rule
    'VT-042': 'family',   # "Buffer Overflow" vs "Improper Handling of Length Parameter Inconsistency (CWE-130)" — CWE-130 is under CWE-119 buffer family
    'VT-043': 'exact',    # "Server-Side Request Forgery" — alias of CWE-918
    'VT-044': 'exact',    # same
    'VT-045': 'exact',    # "Symlink Following" vs multi-GT including CWE-61 "UNIX Symbolic Link Following" — exact under any-rule
    'VT-046': 'exact',    # "Cross-Site Scripting" — alias of CWE-79
    'VT-047': 'miss',     # "Privilege Escalation" vs "Uncontrolled Search Path Element" — impact vs mechanism
    'VT-048': 'miss',     # "Denial of Service" vs CWE-248+CWE-1321 — DoS is impact
    'VT-049': 'exact',    # "Integer Overflow" == "Integer Overflow or Wraparound" — key term matches
    'VT-050': 'exact',    # multi-GT: against CWE-190 "Integer Overflow or Wraparound" — exact under any-rule
    'VT-051': 'exact',    # multi-GT: against CWE-502 "Deserialization of Untrusted Data" — exact under any-rule
    'VT-052': 'miss',     # "Denial of Service" vs "Improper Resource Shutdown or Release" — DoS is impact
    'VT-053': 'miss',     # "Embedded Malicious Code (CWE-506)" vs "Code Injection (CWE-94)" — different CWEs
    'VT-054': 'family',   # "Improper Authorization" vs "Incorrect Privilege Assignment (CWE-266)" — same access control family
    'VT-055': 'exact',    # multi-GT: against CWE-918 SSRF — exact under any-rule
    'VT-056': 'exact',    # "PHP Object Injection" — specific form of CWE-502, functionally equivalent alias
    'VT-057': 'exact',    # "Missing Authorization" == "Missing Authorization"
    'VT-058': 'miss',     # "Resource Exhaustion" vs "Improper Enforcement of Message Integrity (CWE-924)" — different
    'VT-059': 'family',   # "Command Injection" vs CWE-78 "OS Command Injection" — CWE-77 parent concept
    'VT-060': 'miss',     # "Improper Authorization" vs "Deserialization of Untrusted Data" — different
    'VT-061': 'miss',     # "Denial of Service" vs CWE-404 — DoS is impact
    'VT-062': 'miss',     # "Improper Authorization" vs "Insufficiently Protected Credentials (CWE-522)" — different
    'VT-063': 'family',   # same as VT-059
    'VT-064': 'miss',     # "Information Disclosure" vs "Missing Release of Memory (CWE-401)" — memory leak ≠ info disclosure
    'VT-065': 'miss',     # "Privilege Escalation" vs "Improper Privilege Management" — attack vs weakness
    'VT-066': 'exact',    # "Cross-Site Scripting" — alias of CWE-79
    'VT-067': 'family',   # "Environment Variable Injection" vs "External Control of System or Configuration Setting (CWE-15)" — specific form of CWE-15
    'VT-068': 'miss',     # "Improper Authorization" vs "Use of Client-Side Authentication (CWE-603)" — different
    'VT-069': 'miss',     # "Privilege Escalation" vs "Uncontrolled Search Path Element" — impact vs mechanism
    'VT-070': 'family',   # "Improper Link Resolution Before File Access" vs "UNIX Symbolic Link Following (CWE-61)" — CWE-59 is parent of CWE-61
    'VT-071': 'exact',    # "Path Traversal" — alias in parenthetical of CWE-22
    'VT-072': 'exact',    # "Uncontrolled Resource Consumption" == same
    'VT-073': 'miss',     # "Denial of Service" vs CWE-404 — DoS is impact
    'VT-074': 'exact',    # "Integer Overflow" == "Integer Overflow or Wraparound"
    'VT-075': 'exact',    # "Uncontrolled Resource Consumption" == same
    'VT-076': 'exact',    # "Use-After-Free" == "Use After Free" (punctuation)
    'VT-077': 'family',   # "Out-of-bounds Read (CWE-125)" vs "Out-of-bounds Write (CWE-787)" — same memory corruption family, wrong direction
    'VT-078': 'miss',     # "Information Leak" vs "Missing Release of Memory (CWE-401)" — memory leak ≠ info leak
    'VT-079': 'family',   # "Path Traversal" vs multi-GT including CWE-36 "Absolute Path Traversal" — parent vs child under any-rule
    'VT-080': 'miss',     # "Denial of Service" vs CWE-404 — DoS is impact
    'VT-081': 'exact',    # "Use-After-Free" == "Use After Free"
    'VT-082': 'miss',     # "Improper Input Validation" vs "Origin Validation Error (CWE-346)" — different specific weaknesses
    'VT-083': 'exact',    # "Cross-Site Scripting" — alias of CWE-79
    'VT-084': 'exact',    # same
    'VT-085': 'exact',    # "Insertion of Sensitive Information into Log File" == same
    'VT-086': 'exact',    # "Double Free" == "Double Free"
    'VT-087': 'miss',     # "Denial of Service" vs "Missing Release of Resource (CWE-772)" — DoS is impact
    'VT-088': 'exact',    # "Server-Side Template Injection" — common alias for CWE-1336
    'VT-089': 'family',   # "Improper Authorization (CWE-285)" vs "Missing Authorization (CWE-862)" — parent vs child
    'VT-090': 'exact',    # "Use After Free" == "Use After Free"
    'VT-091': 'family',   # "Buffer Overflow" vs "Heap-based Buffer Overflow (CWE-122)" — broader parent
    'VT-092': 'exact',    # "Out-of-bounds Write" == "Out-of-bounds Write"
    'VT-093': 'exact',    # "Cross-Site Scripting" — alias of CWE-79
    'VT-094': 'miss',     # "Denial of Service" vs CWE-404 — DoS is impact
    'VT-095': 'miss',     # "Improper Input Validation" vs "Infinite Loop (CWE-835)" — different
    'VT-096': 'exact',    # "Improper Check or Handling of Exceptional Conditions" == same
    'VT-097': 'exact',    # "SQL Injection" — alias of CWE-89
    'VT-098': 'miss',     # "Authentication Bypass" vs "Incorrect Authorization (CWE-863)" — authn vs authz
    'VT-099': 'miss',     # "Path Traversal" vs CWE-59+CWE-732 — link following ≠ path traversal
    'VT-100': 'family',   # same as VT-022
    'VT-101': 'exact',    # "Information Disclosure" vs multi-GT including CWE-200 "Exposure of Sensitive Information" — semantic alias under any-rule
    'VT-102': 'family',   # "Improper Authorization" vs "Improper Privilege Management (CWE-269)" — same access control family
    'VT-103': 'miss',     # "Improper TLS Enforcement" vs "Improper Certificate Validation (CWE-295)" — related TLS concerns but different weakness
    'VT-104': 'family',   # same as VT-089
    'VT-105': 'family',   # "Out-of-bounds Read" vs "Improper Handling of Length Parameter Inconsistency (CWE-130)" — both under CWE-119
    'VT-106': 'exact',    # "Cross-Site Scripting" — alias of CWE-79
    'VT-107': 'exact',    # "Buffer Over-read" — common alias for "Out-of-bounds Read (CWE-125)"
    'VT-108': 'exact',    # "Integer Overflow" == "Integer Overflow or Wraparound"
    'VT-109': 'family',   # same as VT-059
    'VT-110': 'miss',     # "Information Disclosure" vs "Missing Authorization (CWE-862)" — different
    'VT-111': 'exact',    # "Improper Restriction of Excessive Authentication Attempts" == same (truncated display)
    'VT-112': 'exact',    # "Cross-Site Scripting" — alias of CWE-79
    'VT-113': 'miss',     # "Improper Input Validation" vs "Out-of-bounds Write (CWE-787)" — generic vs specific
    'VT-114': 'exact',    # same as VT-111
    'VT-115': 'exact',    # "Information Disclosure" vs multi-GT including CWE-200 — same as VT-101
    'VT-116': 'family',   # same as VT-089
    'VT-117': 'family',   # same as VT-022
    'VT-118': 'exact',    # "SQL Injection" — alias of CWE-89
    'VT-119': 'family',   # "Uncontrolled Resource Consumption (CWE-400)" vs "Allocation of Resources Without Limits (CWE-770)" — parent vs child
    'VT-120': 'exact',    # "Improper Verification of Cryptographic Signature" == same
    'VT-121': 'miss',     # "Out-of-bounds Read" vs "Uncontrolled Recursion (CWE-674)" — different
    'VT-122': 'exact',    # "Cross-Site Scripting" — alias of CWE-79
    'VT-123': 'miss',     # "Denial of Service" vs CWE-404 — DoS is impact
    'VT-124': 'exact',    # "Buffer Overflow" vs multi-GT including CWE-120 "Classic Buffer Overflow" — near-alias under any-rule
    'VT-125': 'miss',     # "Improper Input Validation" vs "Improper Authorization in Handler for Custom URL Scheme (CWE-939)" — different
    'VT-126': 'family',   # "Insecure Permissions" vs "Incorrect Default Permissions (CWE-276)" — broader informal vs specific
    'VT-127': 'family',   # same as VT-089
    'VT-128': 'exact',    # "Server-Side Request Forgery" — alias of CWE-918
    'VT-129': 'exact',    # "Heap Buffer Overflow" == "Heap-based Buffer Overflow" (phrasing only)
    'VT-130': 'family',   # "Buffer Overflow" vs "Out-of-bounds Write (CWE-787)" — same memory corruption family
    'VT-131': 'miss',     # "Improper Authentication" vs "Insufficient Session Expiration (CWE-613)" — different
    'VT-132': 'exact',    # multi-GT including CWE-77 "Command Injection" — exact under any-rule
    'VT-133': 'family',   # "Improper Input Validation (CWE-20)" vs "Improper Validation of Array Index (CWE-129)" — parent vs specific child
    'VT-134': 'exact',    # "Prototype Pollution" — alias in parenthetical of CWE-1321
    'VT-135': 'family',   # "Improper URL Normalization" vs "Use of Non-Canonical URL Paths for Authorization Decisions (CWE-647)" — related concept
    'VT-136': 'miss',     # "Insufficient Input Validation" vs "Allocation of Resources Without Limits (CWE-770)" — different
    'VT-137': 'miss',     # "Arbitrary Code Execution" vs "Untrusted Search Path (CWE-426)" — impact vs mechanism
    'VT-138': 'miss',     # "Heap Information Disclosure" vs "Missing Release of Memory (CWE-401)" — memory leak ≠ info disclosure
    'VT-139': 'family',   # "Improper Link Resolution" vs "UNIX Symbolic Link Following (CWE-61)" — CWE-59 is parent concept
    'VT-140': 'exact',    # "Use After Free" == "Use After Free"
    'VT-141': 'exact',    # "Path Traversal" — alias of CWE-22
    'VT-142': 'family',   # "Improper Input Validation (CWE-20)" vs "Improper Validation of Specified Type (CWE-1287)" — parent vs child
    'VT-143': 'exact',    # "Path Traversal" — alias of CWE-22
    'VT-144': 'family',   # "Improper Authorization" vs "Incorrect Permission Assignment for Critical Resource (CWE-732)" — same access control family
    'VT-145': 'miss',     # "Code Execution via Malicious Image" vs "Inclusion of Functionality from Untrusted Control Sphere (CWE-829)" — named the attack, not the weakness
    'VT-146': 'family',   # same as VT-022
    'VT-147': 'miss',     # "Resource Leak" vs "Improper Restriction of Operations within Bounds of Memory Buffer (CWE-119)" — different
    'VT-148': 'exact',    # "Command Injection" — alias in parenthetical of CWE-77
    'VT-149': 'miss',     # "Improper Input Validation" vs "Incorrect Permission Assignment (CWE-732)" — different
    'VT-150': 'family',   # "Uncontrolled Resource Consumption (CWE-400)" vs "Memory Allocation with Excessive Size Value (CWE-789)" — parent vs child
    'VT-151': 'exact',    # "TOCTOU Race Condition" — TOCTOU is alias in parenthetical of CWE-367
    'VT-152': 'exact',    # "Time-of-check to time-of-use (TOCTOU)" — matches CWE-367 name and alias
    'VT-153': 'exact',    # "Improper Certificate Validation" == same
    'VT-154': 'exact',    # "Out-of-Bounds Read" == "Out-of-bounds Read" (case only)
    'VT-155': 'exact',    # "Command Injection" — alias in parenthetical of CWE-77
    'VT-156': 'exact',    # same as VT-101 and VT-115
    'VT-157': 'exact',    # "Uncontrolled Resource Consumption" == same
    'VT-158': 'miss',     # "Improper Input Validation" vs "Interpretation Conflict (CWE-436)" — different
    'VT-159': 'exact',    # "OS Command Injection" — alias in parenthetical of CWE-78
    'VT-160': 'miss',     # "Cleartext Storage of Sensitive Information (CWE-312)" vs "Insertion of Sensitive Information into Log File (CWE-532)" — different storage mechanisms
    'VT-161': 'miss',     # "Denial of Service" vs CWE-404 — DoS is impact
    'VT-162': 'miss',     # "Code Execution" vs "Inclusion of Functionality from Untrusted Control Sphere (CWE-829)" — impact vs mechanism
    'VT-163': 'family',   # same as VT-054
    'VT-164': 'exact',    # "Cleartext Transmission of Sensitive Information" == same
    'VT-165': 'miss',     # "Improper Authorization" vs "Incorrect Default Permissions (CWE-276)" — different
    'VT-166': 'exact',    # "Reflected Cross-Site Scripting" — subtype of CWE-79; same core weakness
    'VT-167': 'exact',    # "XML External Entity (XXE) Injection" — common alias for CWE-611
    'VT-168': 'exact',    # multi-GT including CWE-77 "Command Injection" — exact under any-rule
    'VT-169': 'miss',     # "Improper Authorization" vs "Authentication Bypass Using Alternate Path (CWE-288)" — authz vs authn bypass
    'VT-170': 'miss',     # "Improper Input Validation" vs "Incorrect Type Conversion (CWE-704)" — different
    'VT-171': 'miss',     # "Path Traversal" vs CWE-59+CWE-732 — link following ≠ path traversal
    'VT-172': 'family',   # "Stack Overflow" vs "Stack-based Buffer Overflow (CWE-121)" — related but stack overflow is ambiguous (could be CWE-121 or recursion)
    'VT-173': 'miss',     # "Prompt Injection" vs "Improper Neutralization of Special Elements in Template Engine (CWE-1336)" — AI prompt injection ≠ server-side template injection
    'VT-174': 'miss',     # "Denial of Service" vs CWE-404 — DoS is impact
    'VT-175': 'exact',    # "Out-of-bounds Read" == "Out-of-bounds Read"
    'VT-176': 'exact',    # multi-GT includes "Improper Authorization (CWE-285)" — exact under any-rule
    'VT-177': 'exact',    # multi-GT: CWE-89 alias "SQL Injection" — exact under any-rule
    'VT-178': 'exact',    # "Out-of-bounds Write" == "Out-of-bounds Write"
    'VT-179': 'family',   # same as VT-144
    'VT-180': 'miss',     # "Improper Input Validation" vs "Out-of-bounds Read (CWE-125)" — generic vs specific
    'VT-181': 'exact',    # "Command Injection" — alias of CWE-77
    'VT-182': 'exact',    # "Use-After-Free" == "Use After Free"
    'VT-183': 'exact',    # "Out-of-bounds Read" == "Out-of-bounds Read"
    'VT-184': 'family',   # "Improper Access Control (CWE-284)" vs "Authorization Bypass Through User-Controlled Key (CWE-639)" — parent vs child
    'VT-185': 'miss',     # same as VT-015
    'VT-186': 'exact',    # "Path Traversal" — alias of CWE-22
    'VT-187': 'exact',    # multi-GT: against CWE-918 SSRF — exact under any-rule
    'VT-188': 'family',   # same as VT-022
    'VT-189': 'exact',    # "Regular Expression Denial of Service (ReDoS)" — common alias for CWE-1333
    'VT-190': 'exact',    # "Out-of-bounds Read" == "Out-of-bounds Read"
    'VT-191': 'family',   # "Authentication Brute Force" vs "Improper Restriction of Excessive Authentication Attempts (CWE-307)" — attack name vs enabling weakness
    'VT-192': 'family',   # same as VT-054
    'VT-193': 'family',   # same as VT-184
    'VT-194': 'exact',    # multi-GT: against CWE-190 — exact under any-rule
    'VT-195': 'family',   # "Use-After-Free" vs "Release of Invalid Pointer or Reference (CWE-763)" — both memory management safety issues
    'VT-196': 'miss',     # "Improper Authorization" vs "Improper Certificate Validation (CWE-295)" — different
    'VT-197': 'family',   # same as VT-059
    'VT-198': 'exact',    # "DLL Hijacking" — common name for CWE-427 "Uncontrolled Search Path Element"
    'VT-199': 'family',   # "Buffer Overflow" vs multi-GT CWE-120 "Classic Buffer Overflow" — near-alias but consistent with sample30 human label for this pair
    'VT-200': 'exact',    # "LDAP Injection" — alias in parenthetical of CWE-90
}

# read sheet
in_path = os.path.join(HERE, 'labelling_sheet.csv')
rows = []
with open(in_path, encoding='utf-8') as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    for row in reader:
        row['your_label'] = LABELS[row['item_id']]
        rows.append(row)

# write back
with open(in_path, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

# summary
from collections import Counter
c = Counter(LABELS.values())
print(f'Labels written: {len(LABELS)}')
print(f'  exact:   {c["exact"]}')
print(f'  family:  {c["family"]}')
print(f'  partial: {c["partial"]}')
print(f'  miss:    {c["miss"]}')
