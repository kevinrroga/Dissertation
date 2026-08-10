"""
match_affected_component.py
=============================
Day 2 deliverable (FINAL, locked 22 June).

Locks down how an LLM's free-text "affected component" answer is scored
against the structured NVD CPE ground truth.

----------------------------------------------------------------------
METHOD CHOSEN: normalized token overlap with fuzzy tolerance.
----------------------------------------------------------------------
Two alternatives were considered and rejected:

  (b) Embedding similarity -- rejected. CPE strings are short, formulaic
      tokens (vendor:product:version), not prose, so semantic embedding
      similarity solves a problem that doesn't exist here, while adding
      an unjustifiable arbitrary threshold and a second model dependency
      at ~3,000-call evaluation scale. Harms reproducibility.

  (c) Manual/human judgment -- rejected as the PRIMARY method. Does not
      scale to 500 CVEs x 3 models x 2 conditions = 3,000 judgments.
      Retained only as a validation check on a small sample (see the
      REAL_CASES test suite below, which uses actual CVE/CPE pairs from
      the locked Day 1 dataset rather than invented ones).

(a) Token overlap was chosen because it is deterministic, free, fully
reproducible by anyone reading the rule (no model dependency), and
matches the actual structure of the problem -- both sides reduce to the
same vocabulary once normalized.

----------------------------------------------------------------------
THE LOCKED RULE
----------------------------------------------------------------------
1. Parse the CPE 2.3 string into vendor and product tokens. Underscores
   and hyphens are converted to spaces (not stripped) so compound names
   split into the same words a human would read.
2. Normalize the LLM's free-text answer identically: lowercase, convert
   underscores/hyphens to spaces, strip remaining punctuation, tokenize,
   drop a small stopword list.
3. For each ground-truth token, check for an exact match OR a fuzzy
   match (difflib ratio >= 0.8) against any token in the extracted text.
   Fuzzy matching tolerates minor spelling/wording variation (e.g.
   "httpd" vs "http_server") without permitting loose semantic guessing.
4. Score = (# ground-truth tokens matched) / (# ground-truth tokens).
5. A match additionally requires BOTH:
     - score >= 0.5 (at least half of vendor+product tokens recovered)
     - the FIRST product token specifically is recovered (the most
       brand-distinctive word, e.g. "guardium", "db2", "wordpress")

----------------------------------------------------------------------
WHY THE RULE LOOKS LIKE THIS -- TWO REAL BUGS, FOUND BY TESTING
----------------------------------------------------------------------
Revision 1 (pilot testing, invented cases): an LLM answer that named only
the VENDOR ("an Oracle product") was passing at score=0.5 because vendor
tokens alone made up half the token pool for short product names. Fixed
by requiring at least one product token -- later tightened further, see
Revision 2.

Revision 2 (testing against REAL Day 1 dataset, not invented cases): the
vague answer "an IBM data security product" was passing because the
generic English word "data" happened to also appear in the real product
name "Guardium Data Protection." The LLM named no actual product, but a
coincidental shared word produced a false positive. Fixed by requiring
the FIRST product token specifically (the lead, most distinctive word),
not just any product token.

----------------------------------------------------------------------
KNOWN REMAINING LIMITATION (documented, not fixed)
----------------------------------------------------------------------
This rule cannot distinguish between sibling products from the same
vendor that share a brand prefix -- e.g. IBM "Guardium Data Protection"
vs IBM "Guardium Key Lifecycle Manager" both start with "guardium." An
LLM naming the wrong sibling product will still pass. Correctly
resolving this would require a vendor-specific product taxonomy this
function has no access to. This is flagged here for the Error Analysis
chapter (Day 21) rather than patched, because patching it generically
(e.g. requiring ALL product tokens) would break legitimate partial
matches elsewhere (abbreviations, dropped trailing words like "Server").

----------------------------------------------------------------------
TEST EVIDENCE (both suites run automatically when this file executes)
----------------------------------------------------------------------
Suite 1: 10 hand-written, invented CVE/CPE pairs covering edge cases
         (typos, hallucination, vague answers, compound names, etc).
Suite 2: 5 REAL CVE/CPE pairs taken directly from the locked Day 1
         dataset (build_dataset_output.json), each with a "good" and a
         "flawed" plausible LLM-style answer -- 10 cases total. This is
         the suite that actually satisfies the roadmap's "tested on
         real examples" requirement; Suite 1 alone would not have.
"""

import string
import difflib

FUZZY_THRESHOLD = 0.8   # tolerate minor spelling/wording variation only
MATCH_THRESHOLD = 0.5   # fraction of ground-truth tokens required to count as a match

STOPWORDS = {"the", "a", "an", "and", "of", "in", "for", "to", "is", "are"}


def _normalize(text: str) -> list[str]:
    """Lowercase, convert separators to spaces, strip remaining punctuation, tokenize, drop stopwords."""
    text = text.lower()
    text = text.replace("_", " ").replace("-", " ")
    text = text.translate(str.maketrans("", "", string.punctuation))
    tokens = text.split()
    return [t for t in tokens if t not in STOPWORDS]


def parse_cpe(cpe_string: str) -> dict:
    """
    Parse a CPE 2.3 string: cpe:2.3:a:vendor:product:version:...
    Returns dict with vendor_tokens and product_tokens (underscores/hyphens
    split into separate words, identical normalization to the LLM side).
    """
    parts = cpe_string.split(":")
    if len(parts) < 5:
        raise ValueError(f"Malformed CPE string: {cpe_string}")
    vendor_raw = parts[3]
    product_raw = parts[4]
    return {
        "vendor_tokens": _normalize(vendor_raw),
        "product_tokens": _normalize(product_raw),
    }


def _token_found(gt_token: str, extracted_tokens: list[str]) -> bool:
    """Exact match, or fuzzy match above threshold, against any extracted token."""
    if gt_token in extracted_tokens:
        return True
    for et in extracted_tokens:
        if difflib.SequenceMatcher(None, gt_token, et).ratio() >= FUZZY_THRESHOLD:
            return True
    return False


def match_affected_component(extracted: str, ground_truth_cpe: str, return_score: bool = False):
    """
    Compare an LLM's free-text affected-component answer against the CPE
    ground truth.

    Args:
        extracted: the LLM's free-text answer, e.g. "Apache HTTP Server 2.4.49"
        ground_truth_cpe: the NVD CPE 2.3 string, e.g.
                           "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        return_score: if True, return the float score instead of bool

    Returns:
        bool match decision, or float score in [0, 1] if return_score=True.
    """
    if not extracted or not extracted.strip():
        return 0.0 if return_score else False

    cpe = parse_cpe(ground_truth_cpe)
    vendor_tokens = cpe["vendor_tokens"]
    product_tokens = cpe["product_tokens"]
    gt_tokens = vendor_tokens + product_tokens
    if not gt_tokens:
        return 0.0 if return_score else False

    extracted_tokens = _normalize(extracted)

    matched = sum(1 for t in gt_tokens if _token_found(t, extracted_tokens))
    score = matched / len(gt_tokens)

    first_product_token_recovered = (
        _token_found(product_tokens[0], extracted_tokens) if product_tokens else False
    )

    if return_score:
        return score
    return score >= MATCH_THRESHOLD and first_product_token_recovered


# ===========================================================================
# TEST SUITE 1 -- invented CVE/CPE pairs, hand-written to cover edge cases
# ===========================================================================

INVENTED_CASES = [
    {
        "desc": "Clean, correct match",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "llm": "The affected component is Apache HTTP Server version 2.4.49.",
        "expect": True,
    },
    {
        "desc": "Correct but uses common abbreviation (httpd vs http_server)",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "llm": "Apache httpd",
        "expect": True,
    },
    {
        "desc": "Vendor correct, product wrong (different Apache project)",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "llm": "Apache Tomcat",
        "expect": False,
    },
    {
        "desc": "Vague/generic answer with no real signal",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "llm": "A web server application",
        "expect": False,
    },
    {
        "desc": "Multi-word product, vendor omitted by LLM",
        "cpe": "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*",
        "llm": "Internet Information Services (IIS) 10.0",
        "expect": True,
    },
    {
        "desc": "Single-word product, vendor present, product missing",
        "cpe": "cpe:2.3:a:oracle:mysql:8.0.34:*:*:*:*:*:*:*",
        "llm": "An Oracle product, exact component unclear from the description.",
        "expect": False,
    },
    {
        "desc": "Underscore-split product correctly recovered as separate words",
        "cpe": "cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*",
        "llm": "WordPress core software, version 6.4.2",
        "expect": True,
    },
    {
        "desc": "Completely unrelated answer (hallucinated component)",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "llm": "OpenSSL cryptographic library",
        "expect": False,
    },
    {
        "desc": "Typo in LLM output, still recoverable via fuzzy match",
        "cpe": "cpe:2.3:a:nginx:nginx:1.21.0:*:*:*:*:*:*:*",
        "llm": "Nginnx web server",
        "expect": True,
    },
    {
        "desc": "Compound vendor name, hyphen split correctly",
        "cpe": "cpe:2.3:a:node-red:node-red:3.0.0:*:*:*:*:*:*:*",
        "llm": "Node-RED flow-based development tool",
        "expect": True,
    },
]


# ===========================================================================
# TEST SUITE 2 -- REAL CVE/CPE pairs from the locked Day 1 dataset
# (build_dataset_output.json), each with a "good" and "flawed" plausible
# LLM-style answer. The Guardium sibling-product case is intentionally
# marked as a known, accepted limitation rather than a bug -- see module
# docstring above.
# ===========================================================================

REAL_CASES = [
    {
        "cve_id": "CVE-2025-36074",
        "cpe": "cpe:2.3:a:ibm:security_verify_directory:*:*:*:*:*:*:*:*",
        "llm_good": "IBM Security Verify Directory (Container) versions 10.0.0 through 10.0.0.3",
        "expect_good": True,
        "llm_flawed": "A directory service product affected by improper file type validation",
        "expect_flawed": False,
    },
    {
        "cve_id": "CVE-2026-1272",
        "cpe": "cpe:2.3:a:ibm:guardium_data_protection:12.0:*:*:*:*:*:*:*",
        "llm_good": "IBM Guardium Data Protection, versions 12.0-12.2",
        "expect_good": True,
        "llm_flawed": "IBM Guardium (the Key Lifecycle Manager component)",
        "expect_flawed": True,  # KNOWN LIMITATION: sibling product, shares brand prefix "guardium" -- see docstring
        "known_limitation": True,
    },
    {
        "cve_id": "CVE-2026-1274",
        "cpe": "cpe:2.3:a:ibm:guardium_data_protection:12.0:*:*:*:*:*:*:*",
        "llm_good": "Guardium Data Protection access management panel (IBM)",
        "expect_good": True,
        "llm_flawed": "An IBM data security product",
        "expect_flawed": False,
    },
    {
        "cve_id": "CVE-2026-1352",
        "cpe": "cpe:2.3:a:ibm:db2:*:*:*:*:*:linux:*:*",
        "llm_good": "IBM Db2 (including Db2 Connect Server) for Linux, UNIX, and Windows",
        "expect_good": True,
        "llm_flawed": "IBM's database query engine",
        "expect_flawed": False,
    },
    {
        "cve_id": "CVE-2026-1726",
        "cpe": "cpe:2.3:a:ibm:guardium_key_lifecycle_manager:4.1.0:*:*:*:*:*:*:*",
        "llm_good": "IBM Guardium Key Lifecycle Manager, versions 4.1 through 5.1",
        "expect_good": True,
        "llm_flawed": "IBM Guardium Data Protection",
        "expect_flawed": False,
    },
]


def run_invented_suite():
    print("SUITE 1 -- invented edge-case pairs")
    print(f"{'Description':<55} {'Score':>6} {'Pred':>6} {'Expect':>7} {'Result':>10}")
    print("-" * 90)
    n_correct = 0
    for case in INVENTED_CASES:
        score = match_affected_component(case["llm"], case["cpe"], return_score=True)
        pred = match_affected_component(case["llm"], case["cpe"])
        ok = pred == case["expect"]
        n_correct += int(ok)
        print(f"{case['desc']:<55} {score:>6.2f} {str(pred):>6} {str(case['expect']):>7} {'OK' if ok else 'MISMATCH':>10}")
    print("-" * 90)
    print(f"{n_correct}/{len(INVENTED_CASES)} matched expectation.\n")
    return n_correct, len(INVENTED_CASES)


def run_real_suite():
    print("SUITE 2 -- REAL CVE/CPE pairs from locked Day 1 dataset")
    print(f"{'CVE':<18} {'Variant':<10} {'Score':>6} {'Pred':>6} {'Expect':>7} {'Result':>20}")
    print("-" * 90)
    n_correct = 0
    n_total = 0
    for case in REAL_CASES:
        for variant, llm_key, expect_key in [("good", "llm_good", "expect_good"), ("flawed", "llm_flawed", "expect_flawed")]:
            score = match_affected_component(case[llm_key], case["cpe"], return_score=True)
            pred = match_affected_component(case[llm_key], case["cpe"])
            ok = pred == case[expect_key]
            n_correct += int(ok)
            n_total += 1
            if variant == "flawed" and case.get("known_limitation"):
                result = "OK (known limitation)"
            else:
                result = "OK" if ok else "MISMATCH"
            print(f"{case['cve_id']:<18} {variant:<10} {score:>6.2f} {str(pred):>6} {str(case[expect_key]):>7} {result:>20}")
    print("-" * 90)
    print(f"{n_correct}/{n_total} matched expectation on real data.\n")
    return n_correct, n_total


if __name__ == "__main__":
    inv_ok, inv_total = run_invented_suite()
    real_ok, real_total = run_real_suite()

    print("=" * 90)
    print("DAY 2 'DONE WHEN' CHECK")
    print("=" * 90)
    total_ok = inv_ok + real_ok
    total_cases = inv_total + real_total
    print(f"Invented edge cases: {inv_ok}/{inv_total}")
    print(f"Real Day 1 data:     {real_ok}/{real_total}")
    if total_ok == total_cases:
        print("PASS: match_affected_component() behaves as expected on every test case, "
              "including real CVE/CPE pairs. One known, documented limitation (Guardium "
              "sibling-product ambiguity) is accepted, not silently failing.")
    else:
        print(f"FAIL: {total_cases - total_ok} unexplained mismatch(es) -- investigate before "
              f"trusting this function on the full dataset.")