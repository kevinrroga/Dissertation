"""
run_fewshot.py — Day 13-14 full few-shot run  (CORRECTED)
========================================================
3 models x 500 CVEs = 1,500 calls, few-shot condition.

WHAT WAS WRONG IN THE PREVIOUS VERSION (and is now fixed):
  1. call_gpt5/call_claude/call_deepseek were NotImplementedError stubs, so
     every call failed with "Paste your zero-shot ... call here". The real,
     working bodies (from test_few_shot_prompt.py / Day 7) are now inlined.
  2. The model list said "claude-opus-4.7". Every other file in the project
     (zero-shot Day 11, Day 6, Day 7) uses "claude-sonnet-4.6". Opus 4.7+
     rejects a user-set temperature (400 error), which would crash every
     Claude call AND break RQ2 (you'd compare few-shot-Opus vs zero-shot-
     Sonnet). Corrected to claude-sonnet-4.6, matching the zero-shot snapshot.
  3. The leakage gate checked examples_file.json, but the prompt taught from
     a DIFFERENT hardcoded set of examples. The gate was theatre. This
     version refuses to run unless the prompt's example CVE ids and
     examples_file.json's ids are the SAME three, so the check actually
     governs what the model sees.

BEFORE YOU RUN — you must resolve ONE methodological decision:
  Your Day-7 exemplars were drawn from INSIDE the locked 500-CVE set. For the
  real experiment that is data leakage for RQ2. Pick one, set RESOLVED = True:
    ROUTE A: replace the 3 exemplars with 3 CVEs OUTSIDE the 500, rebuild the
             prompt to use them, and keep n=500 scored.
    ROUTE B: keep the 3 inside-set exemplars but EXCLUDE them from scoring
             under BOTH conditions (n=497), documented in your Decision Log.
  This script cannot choose for you. It only enforces that whatever you chose
  is internally consistent.
"""

import os
import re
import json
import time
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

_ROOT = Path(__file__).resolve().parent.parent

# ----------------------------- CONFIG -----------------------------
PROMPT_FILE      = str(_ROOT / "few_shot" / "few_shot_prompt.txt")
EXAMPLES_FILE    = str(_ROOT / "few_shot" / "examples_file.json")
LOCKED_DATASET   = str(_ROOT / "ultimate_dataset" / "dataset_v1_locked_24jun_with_cwe_names.json")
OUTPUT_JSONL     = str(_ROOT / "few_shot" / "results_fewshot-new_file.jsonl")
CONDITION        = "few_shot"
TEMPERATURE      = 0.0

# --- Set this True only AFTER you have resolved the leakage decision above. ---
# ROUTE A confirmed 5 Jul 2026: all 3 exemplars below were drawn from
# data/prompts/diverse_candidates.json, verified disjoint from the locked
# 500-CVE eval set (dataset_v1_locked_24jun.json). n=500, no exclusions.
RESOLVED = True
# The exact three CVE ids your few-shot prompt teaches from. These MUST match
# the ids in examples_file.json AND the examples baked into few_shot_prompt.txt.
# (If you go ROUTE B, list the three inside-set ids here and also add them to
#  EXCLUDE_FROM_SCORING so your Day-18 scorer drops them under both conditions.)
EXPECTED_EXAMPLE_IDS = {"CVE-2026-11281", "CVE-2026-11245", "CVE-2026-25657"}
EXCLUDE_FROM_SCORING = set()   # ROUTE B only: the inside-set exemplar ids to drop

REQUIRED_KEYS = [
    "vulnerability_type",
    "attack_vector",
    "affected_component",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]
ALLOWED_AV  = {"Network", "Adjacent Network", "Local", "Physical", None}
ALLOWED_CIA = {"None", "Low", "High", None}

# Model ids matched to the zero-shot run. DO NOT change claude to Opus.
MODELS = ["gpt-5.5", "claude-sonnet-4.6", "deepseek-v4-pro"]
RATE_DELAY = {"gpt-5.5": 1.0, "claude-sonnet-4.6": 1.0, "deepseek-v4-pro": 0.5}


# --------------------- MODEL CALLS (real bodies, from Day 7) ---------------------
def _require_key(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} not found in environment. Check your .env file contains "
            f"a line like: {name}=your-key-here."
        )
    return value


def call_gpt5(prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=_require_key("OPENAI_API_KEY"))
    response = client.responses.create(
        model="gpt-5.5",
        input=prompt,
        reasoning={"effort": "none"},   # reasoning-off, matches zero-shot
        temperature=0,                  # greedy decoding
    )
    return response.output_text


def call_claude(prompt: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=_require_key("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model="claude-sonnet-4-6",      # Sonnet 4.6 — accepts temperature; matches zero-shot
        max_tokens=1024,
        temperature=0,                  # greedy decoding
        messages=[{"role": "user", "content": prompt}],
        # No `thinking` param -> extended thinking stays off.
    )
    return response.content[0].text


def call_deepseek(prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(
        api_key=_require_key("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )
    response = client.chat.completions.create(
        model="deepseek-v4-pro",
        messages=[{"role": "user", "content": prompt}],
        temperature=0,                                  # honoured only with thinking off
        extra_body={"thinking": {"type": "disabled"}},  # reasoning off (V4 defaults ON)
    )
    return response.choices[0].message.content


CALLERS = {
    "gpt-5.5": call_gpt5,
    "claude-sonnet-4.6": call_claude,
    "deepseek-v4-pro": call_deepseek,
}


# ------------------------- RETRY (from Day 7, transient-only) -------------------------
RETRYABLE_SIGNALS = (
    "503", "UNAVAILABLE", "overloaded",
    "429", "rate limit", "RateLimit", "Too Many Requests",
    "timeout", "Timeout", "ETIMEDOUT",
    "500", "InternalServerError", "ServiceUnavailable",
)

def call_with_retry(fn, prompt, label="model", max_attempts=3,
                    base_backoff=3, max_backoff=60):
    import random
    last_error = None
    backoff = base_backoff
    for attempt in range(1, max_attempts + 1):
        try:
            return fn(prompt)
        except Exception as e:
            last_error = e
            if not any(sig in str(e) for sig in RETRYABLE_SIGNALS):
                raise                       # real error — don't retry
            if attempt < max_attempts:
                wait = min(backoff, max_backoff) + random.uniform(0, 2)
                print(f"    [retry] {label} transient error "
                      f"(attempt {attempt}/{max_attempts}); waiting {wait:.1f}s")
                time.sleep(wait)
                backoff *= 2
            else:
                raise
    raise last_error


# ------------------------------ PROMPT ------------------------------
def load_prompt_template(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        tpl = f.read()
    if "{description}" not in tpl:
        sys.exit(f"FATAL: {path} has no {{description}} placeholder. Aborting.")
    return tpl

def build_prompt(template: str, description: str) -> str:
    return template.replace("{description}", description)


# ---------------------------- VALIDATION ----------------------------
def strip_code_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()

def validate(raw: str):
    cleaned = strip_code_fences(raw)
    try:
        obj = json.loads(cleaned)
    except json.JSONDecodeError as e:
        return None, f"json_parse_error: {e}"
    if not isinstance(obj, dict):
        return None, "not_a_json_object"
    missing = [k for k in REQUIRED_KEYS if k not in obj]
    if missing:
        return None, f"missing_keys: {missing}"
    if obj.get("attack_vector") not in ALLOWED_AV:
        return None, f"bad_attack_vector: {obj.get('attack_vector')!r}"
    for k in ("confidentiality_impact", "integrity_impact", "availability_impact"):
        if obj.get(k) not in ALLOWED_CIA:
            return None, f"bad_{k}: {obj.get(k)!r}"
    return {k: obj[k] for k in REQUIRED_KEYS}, None


# ---------------------------- CHECKPOINT ----------------------------
def load_completed(path: str) -> set:
    done = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    row = json.loads(line)
                    done.add((row["cve_id"], row["model"], row["prompt_condition"]))
    return done

def append_row(path: str, row: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
        f.flush()
        os.fsync(f.fileno())


# ------------------- CONSISTENCY + LEAKAGE GATES -------------------
def assert_decision_made():
    if not RESOLVED:
        sys.exit(
            "STOP: RESOLVED is False. You have not settled the few-shot leakage\n"
            "decision (exemplars were drawn from inside the locked 500-set).\n"
            "Pick ROUTE A (outside-set exemplars, n=500) or ROUTE B (exclude the\n"
            "3 exemplars from scoring, n=497), set EXPECTED_EXAMPLE_IDS, then set\n"
            "RESOLVED = True. See the header of this file."
        )
    if not EXPECTED_EXAMPLE_IDS:
        sys.exit("STOP: RESOLVED is True but EXPECTED_EXAMPLE_IDS is empty. "
                 "List the exact 3 exemplar CVE ids your prompt uses.")

def assert_examples_consistent(template: str, examples):
    """The 3 ids in examples_file.json, the 3 you declared in
    EXPECTED_EXAMPLE_IDS, and the ids that actually appear in the prompt text
    must all be the same set. Otherwise the leakage check is meaningless."""
    file_ids = {e["cve_id"] for e in examples}
    if file_ids != EXPECTED_EXAMPLE_IDS:
        sys.exit(f"STOP: examples_file.json ids {sorted(file_ids)} != "
                 f"EXPECTED_EXAMPLE_IDS {sorted(EXPECTED_EXAMPLE_IDS)}.")
    # Every declared exemplar id should be findable in the prompt, so the
    # prompt and the file cannot silently diverge.
    missing_in_prompt = [cid for cid in EXPECTED_EXAMPLE_IDS if cid not in template]
    if missing_in_prompt:
        print("WARNING: these exemplar ids are not literally present in the prompt "
              f"text: {missing_in_prompt}. If your prompt intentionally omits CVE ids, "
              "confirm by hand that the worked examples in the prompt correspond to "
              "these CVEs before proceeding.")

def assert_no_leakage(eval_cves, example_ids):
    eval_ids = {c["cve_id"] for c in eval_cves}
    overlap = eval_ids & example_ids
    if overlap and not EXCLUDE_FROM_SCORING >= overlap:
        sys.exit(f"FATAL: exemplar CVEs are inside the eval set and NOT marked for "
                 f"exclusion: {sorted(overlap)}. Either use outside-set exemplars "
                 f"(ROUTE A) or add these to EXCLUDE_FROM_SCORING (ROUTE B).")
    if overlap:
        print(f"Leakage acknowledged (ROUTE B): {sorted(overlap)} are inside the set "
              f"and WILL be excluded from scoring under both conditions (n="
              f"{len(eval_ids) - len(overlap)}).")
    else:
        print(f"Leakage check passed (ROUTE A): {len(example_ids)} exemplars, none "
              f"in the {len(eval_ids)}-CVE eval set.")


# ------------------------------- RUN --------------------------------
def format_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"

def run_one(model, template, cve):
    prompt = build_prompt(template, cve["description"])
    raw, parsed, err = "", None, None
    try:
        raw = call_with_retry(CALLERS[model], prompt, label=model)
        parsed, err = validate(raw)
    except Exception as e:
        raw, err = "", f"api_error: {e}"
    return {
        "cve_id": cve["cve_id"],
        "model": model,
        "prompt_condition": CONDITION,
        "extracted": parsed,
        "failure_reason": err,
        "raw_response": raw,
    }

def main():
    assert_decision_made()

    template  = load_prompt_template(PROMPT_FILE)
    eval_cves = json.load(open(LOCKED_DATASET, encoding="utf-8"))
    examples  = json.load(open(EXAMPLES_FILE, encoding="utf-8"))
    example_ids = {e["cve_id"] for e in examples}

    if len(sys.argv) > 1:
        limit = int(sys.argv[1])
        eval_cves = eval_cves[:limit]

    assert_examples_consistent(template, examples)
    assert_no_leakage(eval_cves, example_ids)

    completed = load_completed(OUTPUT_JSONL)
    target = len(eval_cves) * len(MODELS)
    done_count = len(completed)
    print(f"Resuming: {done_count}/{target} calls already done.\n")

    run_start = time.time()
    fails = {m: 0 for m in MODELS}
    for model in MODELS:
        last = 0.0
        for i, cve in enumerate(eval_cves, 1):
            key = (cve["cve_id"], model, CONDITION)
            if key in completed:
                continue
            wait = RATE_DELAY[model] - (time.time() - last)
            if wait > 0:
                time.sleep(wait)
            last = time.time()

            call_start = time.time()
            row = run_one(model, template, cve)
            call_elapsed = time.time() - call_start
            append_row(OUTPUT_JSONL, row)

            done_count += 1
            if row["extracted"] is None:
                fails[model] += 1
                status = f"FAIL ({row['failure_reason']})"
            else:
                status = "ok"
            total_elapsed = time.time() - run_start
            print(f"[{model}] {i}/{len(eval_cves)} {cve['cve_id']} -> {status} "
                  f"| call {call_elapsed:.1f}s | total {done_count}/{target} "
                  f"| elapsed {format_duration(total_elapsed)}")

    total_elapsed = time.time() - run_start
    print("\n=== FEW-SHOT RUN COMPLETE ===")
    for m in MODELS:
        print(f"{m}: {fails[m]} failures / {len(eval_cves)}")
    print(f"Total run time: {format_duration(total_elapsed)}")
    print("Log these failure counts in your Decision Log (Day 13-14).")

if __name__ == "__main__":
    main()