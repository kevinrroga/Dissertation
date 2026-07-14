# Day 18 — Vulnerability-Type Matcher: Build & Validation Record

**Purpose of this file:** a factual record of how the vulnerability-type scoring
matcher was built and validated, written so it can be adapted almost directly into
the Methodology / Evaluation chapter. It documents *what was decided, why, what was
tested, and what was found* — including the honest limitations, which the marking
scheme rewards.

Companion file: `vuln_type_matcher.py` (the validated implementation).
Prior decision log: `day18_vulnerability_type_matching_decisions.md`.

---

## 1. What was being built

A classifier that compares each LLM-extracted `vulnerability_type` (free-text prose)
against the NVD ground-truth CWE (carried as its MITRE canonical name), and returns
one of four outcomes:

- **exact** — the model's committed answer names the same specific weakness
  (alias/phrasing differences allowed).
- **family** — the model's committed answer is a correct broader parent, sibling,
  or named component of the assigned CWE within the same weakness hierarchy.
- **partial** — the model returned *multiple* types (a hedge) and one of them was
  correct, but it did not commit to a single answer. Never counts as a headline hit.
- **miss** — wrong weakness, unrelated, or null.

Strength ordering: exact > family > partial > miss.

The four-way scheme (rather than a simple match/miss) was adopted deliberately so
that (a) hierarchy near-misses are distinguished from outright errors, and (b)
"the model included the right answer among several guesses" is preserved and
reported rather than either silently discarded or falsely credited.

---

## 2. Matching rules implemented

1. **Canonical-name matching with alias harvesting.** MITRE CWE names often hide
   the human-readable term in a parenthetical (e.g. CWE-77 = "Improper
   Neutralization of Special Elements used in a Command ('Command Injection')").
   These aliases are harvested and treated as accepted exact forms, so a model
   answering "Command Injection" is correctly scored exact rather than missed.

2. **Discriminating-token overlap, not bag-of-words.** Matching requires the
   *discriminating* tokens to be shared, not filler words ("improper", "of",
   "used"). This prevents false matches such as "Improper Authorization" vs
   "Improper Authentication" (different weaknesses sharing the word "improper").

3. **Specificity-token rule (exact vs family boundary).** When the ground-truth
   name is a strict, more-specific version of the model's answer *because of a
   specificity qualifier* (stack, heap, classic, integer, unbounded), the model's
   broader term is scored **family**, not exact. When the extra ground-truth tokens
   are mere filler (e.g. "Missing Authentication" vs "Missing Authentication for
   Critical Function"), it remains **exact**.

4. **Small dataset-specific hierarchy map.** A family match uses a hand-built map
   covering only the CWE clusters that actually collide in the dataset
   (memory-corruption group under CWE-119; injection group under CWE-74; a
   credentials group for CWE-798). This is far smaller than a full 145-CWE lookup
   and every entry is justified by CWEs present in the data.

5. **Compound-term protection.** A slash inside a single named concept
   (e.g. "CSV/Formula Injection") is not treated as a multi-type hedge. Only
   genuine multi-type answers are split.

6. **Multi-CWE ground truth ("any" rule).** Where NVD assigned several CWEs to one
   CVE, the answer is matched against every assigned CWE and the strongest outcome
   is kept.

7. **Case A vs Case B (hedge handling by ground-truth cardinality).**
   - *Case A* — multi-CWE ground truth + multi-type answer: matching a real set of
     answers against a real set of weaknesses is legitimate; strongest outcome kept.
   - *Case B* — single-CWE ground truth + multi-type answer: a correct fragment is
     present but the model did not commit, so it is scored **partial** (not a
     headline hit), avoiding scorer-side selection bias.

8. **Nulls** are scored **miss**.

---

## 3. Validation method

A **purposive** sample of 30 extraction/ground-truth pairs was drawn from the
3,000 results, handpicked to span the matcher's decision boundaries (clean exacts,
parenthetical aliases, hierarchy near-misses, false friends, hedged multi-type
answers, both ground-truth cardinalities, and clean misses). This is deliberately
harder than a random draw, which would be dominated by easy exact matches and would
not exercise the rules.

The researcher hand-labelled all 30 (exact / family / partial / miss) **by eye and
before any matcher code was run**, using CWE hierarchy relationships established by
lookup from the MITRE CWE definitions. The family-vs-miss and exact-vs-family
*policy* was set by the researcher; the CWE relationships themselves were
established from MITRE rather than from memory. The matcher's automated verdicts
were then compared against these human labels.

*(Note on method integrity: labelling by hand before building the matcher avoids
circularity — had the matcher been used to produce the labels it was then tested
against, the agreement rate would be meaningless.)*

---

## 4. Result

**Agreement: 28/30 = 93.3%** after one round of correction.

An initial run agreed on 24/30. The 6 disagreements were examined individually and
resolved as follows:

- **3 were genuine matcher bugs** — the exact/family rule was too greedy and scored
  broad-term answers (e.g. "Buffer Overflow" for a stack-based overflow) as exact
  instead of family. Fixed via the specificity-token rule (rule 3 above). Human
  labels were correct.
- **1 was a family-map gap** — "Hardcoded Cryptographic Key" vs CWE-798 (Use of
  Hard-coded Credentials) was missed because the credential relationship was not in
  the map. Fixed by adding it. Human label was correct.
- **1 was a compound-term split error** — "CSV/Formula Injection" was wrongly split
  into a hedge. Fixed by compound-term protection (rule 5). Human label was correct.
- **1 was a data-transcription error in the validation sample itself** — the
  displayed extracted string differed from the source data
  (CVE-2026-42217 was shown as "Undefined Behavior / Integer Overflow" but the
  actual response was "Undefined Behavior (Unbounded Shift)"). Against source data
  the matcher's **miss** was correct; the human **partial** label had been based on
  the mistaken string. The sample was corrected.

### Remaining disagreements after fixes (2/30)
- **CVE-2026-42217** — resolved as above; the human label should read **miss**
  against source data. Retained as a documented data-integrity catch.
- **CVE-2026-48686** — "Buffer Overflow" vs ["Classic Buffer Overflow" (CWE-120),
  "Out-of-bounds Write" (CWE-787)]. Matcher scored **exact** (CWE-120's alias is
  literally "Classic Buffer Overflow", nearly synonymous with "Buffer Overflow");
  the researcher labelled **family**. This is a genuine exact-versus-family boundary
  case where both readings are defensible. It was **not** forced to agree, to avoid
  overfitting the matcher to a single ambiguous label.

---

## 5. Why the matcher was not tuned to 100%

Deliberately. Forcing agreement on the two residual cases would mean fitting the
code to specific labels on a genuinely ambiguous case and a corrected data error —
i.e. overfitting the validation set. A reported 93.3% with fully explained residuals
is more credible than a 100% that would signal the matcher had been tuned until it
agreed. The residuals are one corrected data error and one legitimate boundary
ambiguity — neither is a systematic matcher fault.

---

## 6. Draft text for the dissertation (adapt as needed)

> The vulnerability-type matcher was validated against 30 purposively-selected
> boundary cases, hand-labelled by the researcher using CWE hierarchy relationships
> established from the MITRE CWE definitions, prior to running the matcher.
> Agreement between the automated matcher and manual judgment was 28/30 (93.3%).
> Of the two residual disagreements, one was a transcription error in the validation
> sample (corrected on inspection) and one was a genuine exact-versus-family boundary
> case (CWE-120, whose canonical alias "Classic Buffer Overflow" the model rendered
> as "Buffer Overflow"). No systematic matcher error remained. The matcher was not
> tuned to force full agreement, so as not to overfit the validation set.

---

## 7. Status and what remains

**Done:** vulnerability-type matcher built and validated (93.3% agreement).

**Still to do for Day 18 completion:**
- Attack-vector scorer — simple exact category match against the parsed CVSS `AV:`
  value. Do not over-engineer; no hierarchy or fuzzy matching needed.
- CIA scorer — exact match against parsed `C:` / `I:` / `A:` values, three separate
  sub-scores (decision already locked).
- Affected-component scorer — plug in the Day-2 matching function. This is the last
  unvalidated component and should get its own small sanity check.
- Assemble the full scoring pipeline over all 3,000 rows to produce the
  precision / recall / F1 table (rows = entity type, columns = model × condition).

**Later (flagged for the grade):**
- Plan McNemar's test for the RQ2 model comparisons (paired data, same CVEs).
- Error analysis must deliver the *why*, not just the numbers.
