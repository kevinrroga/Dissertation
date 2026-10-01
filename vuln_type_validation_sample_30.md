# Vulnerability-Type Matcher: 30-Pair Validation Sample (purposive)

**How to use this:** For each row, look at the model's `extracted` answer and the
NVD `ground_truth` canonical name, and write your own judgment in the **LABEL**
column: `exact`, `family`, or `miss`. Do this *by eye, before* running any
matcher code; these labels are the human ground truth the matcher will be tested
against. The agreement rate between your labels and the matcher's verdicts is what
you report as validation.

**Label definitions (decide consistently):**
- **exact** = model named the same specific weakness NVD did (allowing for
  phrasing/alias differences).
- **family** = model named a correct *broader* category or parent of the NVD
  weakness (right family, wrong specificity).
- **miss** = wrong weakness, or no defensible match.

**Sampling note (for the write-up):** this is a *purposive* sample, handpicked to
span the matcher's decision boundaries (exact, alias, hierarchy near-miss, false
friends, hedged multi-type, both ground-truth cardinalities, clean miss). It is
deliberately harder than a random draw; random would be mostly easy exacts and
would not exercise the rule. Describe it as purposive, not random.

---

## Group 1: Clean / alias exacts (should be `exact`; tests you don't break easy cases)

| # | CVE | Model | Extracted | Ground-truth canonical | CWE | LABEL |
|---|-----|-------|-----------|------------------------|-----|-------|
| 1 | CVE-2026-49198 | gpt-5.5 | Improper Access Control | Improper Access Control | CWE-284 | ______ |
| 2 | CVE-2026-46579 | gpt-5.5 | Improper Authentication | Improper Authentication | CWE-287 | ______ |
| 3 | CVE-2026-42965 | gpt-5.5 | Server-Side Request Forgery | Server-Side Request Forgery (SSRF) | CWE-918 | ______ |
| 4 | CVE-2026-49195 | gpt-5.5 | Missing Authentication | Missing Authentication for Critical Function | CWE-306 | ______ |
| 5 | CVE-2026-46242 | gpt-5.5 | Use-After-Free | Use After Free | CWE-416 | ______ |

*Why: #3 tests the parenthetical alias; #4 tests truncated-but-correct; #5 tests
punctuation/spacing ("Use-After-Free" vs "Use After Free").*

---

## Group 2: Parenthetical-alias / injection exacts (tests alias harvesting)

| # | CVE | Model | Extracted | Ground-truth canonical | CWE | LABEL |
|---|-----|-------|-----------|------------------------|-----|-------|
| 6 | CVE-2026-49196 | gpt-5.5 | Command Injection | Improper Neutralization of Special Elements used in a Command ('Command Injection') | CWE-77 | ______ |
| 7 | CVE-2025-41265 | gpt-5.5 | OS Command Injection | Improper Neutralization... ('OS Command Injection') | CWE-78 | ______ |
| 8 | CVE-2026-42267 | gpt-5.5 | CSV/Formula Injection | Improper Neutralization of Formula Elements in a CSV File | CWE-1236 | ______ |

*Why: for #6 and #7, the real term is only in the parenthetical; plain token overlap on
the full formal name would fail these. #8 has a slash but is ONE concept; this tests
that you don't wrongly split a single-concept answer.*

---

## Group 3: Hierarchy / family near-misses (the most important stratum)

| # | CVE | Model | Extracted | Ground-truth canonical | CWE | LABEL |
|---|-----|-------|-----------|------------------------|-----|-------|
| 9  | CVE-2026-49014 | claude-sonnet-4.6 | Buffer Overflow | Stack-based Buffer Overflow | CWE-121 | ______ |
| 10 | CVE-2018-25426 | gpt-5.5 | Buffer Overflow | Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | CWE-120 | ______ |
| 11 | CVE-2026-43078 | gpt-5.5 | Buffer Overflow | Out-of-bounds Write | CWE-787 | ______ |
| 12 | CVE-2026-8376 | claude-sonnet-4.6 | Buffer Overflow | Integer Overflow to Buffer Overflow | CWE-680 | ______ |
| 13 | CVE-2025-41266 | gpt-5.5 | OS Command Injection | Improper Neutralization... ('OS Command Injection') | CWE-78 | ______ |

*Why: this is where `exact` vs `family` is actually decided. #9: is "Buffer
Overflow" exact for a stack-based overflow, or family? #10: the alias literally
says "Classic Buffer Overflow" (exact?). #11: "Buffer Overflow" for an
out-of-bounds WRITE: same family or a miss? #12 is tricky: the overflow is a
consequence of an integer overflow. Your calls here define your exact/family
boundary; be consistent.*

---

## Group 4: False friends (should mostly be `miss`; tests you don't over-match)

| # | CVE | Model | Extracted | Ground-truth canonical | CWE | LABEL |
|---|-----|-------|-----------|------------------------|-----|-------|
| 14 | CVE-2026-49197 | gpt-5.5 | Improper Authorization | Improper Authentication | CWE-287 | ______ |
| 15 | CVE-2026-39831 | gpt-5.5 | Improper Authentication | Missing Authorization | CWE-862 | ______ |
| 16 | CVE-2026-43617 | gpt-5.5 | Authorization Bypass | Authentication Bypass by Alternate Name | CWE-289 | ______ |
| 17 | CVE-2026-4273 | gpt-5.5 | Improper Authentication | Incorrect Authorization | CWE-863 | ______ |
| 18 | CVE-2026-49201 | gpt-5.5 | Hardcoded Cryptographic Key | Use of Hard-coded Credentials | CWE-798 | ______ |

*Why: #14–17 share filler tokens ("improper", "bypass") but are authz-vs-authn,
genuinely different weaknesses. A naive matcher scores these as matches; they
should be misses. #18 involves hardcoded KEY vs hardcoded CREDENTIALS: close but is it
the same CWE? Your call.*

---

## Group 5: Hedged multi-type answers (tests the cardinality-split rule)

| # | CVE | Model | Extracted | Ground-truth canonical | CWE | GT card. | LABEL |
|---|-----|-------|-----------|------------------------|-----|----------|-------|
| 19 | CVE-2026-45252 | claude-sonnet-4.6 | Buffer Over-read / Heap Buffer Overflow | Heap-based Buffer Overflow | CWE-122 | single | ______ |
| 20 | CVE-2026-45321 | claude-sonnet-4.6 | Pwn Request / Cache Poisoning / Credential Theft Chain | Embedded Malicious Code | CWE-506 | single | ______ |
| 21 | CVE-2026-42217 | claude-sonnet-4.6 | Undefined Behavior / Integer Overflow | Integer Overflow or Wraparound | CWE-190 | single | ______ |
| 22 | CVE-2026-7258 | deepseek-v4-pro | Buffer Under-read / Out-of-bounds Read | Out-of-bounds Read | CWE-125 | single | ______ |
| 23 | CVE-2026-42002 | deepseek-v4-pro | Concurrency/Locking Defect | Signal Handler Race Condition | CWE-364 | single | ______ |
| 24 | CVE-2026-43870 | gpt-5.5 | Path Traversal / HTTP Request/Response Splitting / Uncontrolled Resource Consumption | [Path Traversal; HTTP Req/Resp Splitting; Origin Validation Error; Uncontrolled Resource Consumption] | CWE-22, 113, 346, 400 | MULTI | ______ |

*Why: #19–23 are single-CWE ground truth + hedged answer = your **Case B**
(decision: miss, carried to error analysis). Label what you think the honest
outcome is, THEN check it matches your Case B rule. #24 is **Case A** (multi-CWE
GT + multi answer); three of the model's four types match real NVD CWEs; under
your "any" rule this should be a match. This one row validates the whole
cardinality split.*

---

## Group 6: Clean misses (tests the matcher isn't matching everything)

| # | CVE | Model | Extracted | Ground-truth canonical | CWE | LABEL |
|---|-----|-------|-----------|------------------------|-----|-------|
| 25 | CVE-2026-48840 | gpt-5.5 | Information Disclosure | Numeric Range Comparison Without Minimum Check | CWE-839 | ______ |
| 26 | CVE-2018-25412 | gpt-5.5 | Arbitrary File Upload | Missing Authentication for Critical Function | CWE-306 | ______ |
| 27 | CVE-2026-48210 | gpt-5.5 | Improper Default Configuration | Exposure of Sensitive Information...; Improper Privilege Management | CWE-200, 269 | ______ |
| 28 | CVE-2026-8922 | gpt-5.5 | Improper Authorization | Incorrect Implementation of Authentication Algorithm | CWE-303 | ______ |
| 29 | CVE-2026-6334 | gpt-5.5 | Improper Authorization | Authentication Bypass by Primary Weakness | CWE-305 | ______ |
| 30 | CVE-2026-48686 | deepseek-v4-pro | Buffer Overflow | Classic Buffer Overflow; Out-of-bounds Write | CWE-120, 787 | ______ |

*Why: #25 and #26 are plainly different weaknesses, confirming that misses score as
misses. #27 involves "default configuration" vs the real exposure/privilege CWEs. #30 is
a MULTI-CWE case (Case A), providing a second data point to check "any" matching: "Buffer
Overflow" is the broad parent, and Classic Buffer Overflow (CWE-120) is a direct
child, so under the "any + family" rule this should land as at least a family
match.*

> **Footnote on CVE-2026-48686 (not scored, but worth a sentence in the write-up):**
> On the *same* CVE, GPT and Claude answered **"Stack-based Buffer Overflow"**
> (CWE-121), a *sibling* of the assigned Classic Buffer Overflow (CWE-120),
> not either assigned CWE. This is mild **over-specification**: the model names a
> plausible but unverified subtype NVD did not assign. It's the mirror image of
> the family *under*-specification tracked elsewhere, and worth one line in the
> error analysis as a distinct model behaviour.

---

## After labelling

1. Run your matcher over these same 30.
2. Compare matcher verdict vs your LABEL column, count agreements.
3. Report the agreement rate (e.g. "the matcher agreed with manual judgment on
   27/30 purposively-selected boundary cases"). Investigate every disagreement:
   each one is either a matcher bug to fix or a genuinely ambiguous case worth a
   sentence in the limitations.
4. The disagreements on Group 3 (family boundary) are the most informative:
   they tell you whether your exact/family threshold matches human intuition.
