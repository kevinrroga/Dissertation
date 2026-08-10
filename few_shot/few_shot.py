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
OUTPUT_PATH      = str(_ROOT / "few_shot" / "results_fewshot_v1.json")
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

# Short keys used only for the flattened timing summary below.
MODEL_TIME_KEYS = {
    "gpt-5.5": "gpt_time",
    "claude-sonnet-4.6": "claude_time",
    "deepseek-v4-pro": "deepseek_time",
}
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
# Internal working structure: {model: {cve_id: row}}. Keying by cve_id means
# a retry OVERWRITES the previous row for that CVE instead of appending a
# second one -- this is what made the zero-shot script's duplicate-row bug
# (540 rows for 500 CVEs) structurally impossible here, rather than just
# avoided by convention.
def load_existing_results() -> dict:
    if not os.path.exists(OUTPUT_PATH):
        return {model: {} for model in MODELS}

    try:
        with open(OUTPUT_PATH, encoding="utf-8") as f:
            saved = json.load(f)
    except (json.JSONDecodeError, OSError):
        print("Existing output could not be read. Starting a new result file.")
        return {model: {} for model in MODELS}

    # Saved file format is {model: [row, row, ...]} -- same list-of-rows
    # shape as zero_shot_final.py's output, for direct compatibility at
    # consolidation time. Rebuild the cve_id-keyed working structure from it.
    results = {model: {} for model in MODELS}
    for model in MODELS:
        for row in saved.get(model, []):  # only known model keys are read; timing keys at the top level are ignored here
            cid = row.get("cve_id")
            if cid:
                results[model][cid] = row
    print(f"Resuming from existing file: {OUTPUT_PATH}")
    return results


def save_results(results: dict) -> None:
    """Save after every CVE. Writes to a temp file then atomically renames
    over the target, so a crash mid-write can't corrupt the existing results
    -- unlike a plain overwrite, which could leave a half-written file if
    interrupted (a real risk for JSON, unlike JSONL's append-only safety)."""
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    # Serialize as {model: [row, row, ...]} plus the timing keys (total_time,
    # gpt_time, claude_time, deepseek_time) directly at the top level.
    to_save = {model: list(results[model].values()) for model in MODELS}
    to_save.update(compute_timing_summary(results))
    tmp_path = OUTPUT_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(to_save, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, OUTPUT_PATH)


def completed_cve_ids(results: dict, model: str) -> set:
    """Only genuine successes count as done -- a CVE that previously failed
    stays eligible for retry on resume (unlike the old load_completed(),
    which marked failures as done forever)."""
    return {
        cid for cid, row in results[model].items()
        if row.get("valid") is True
    }


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


def compute_timing_summary(results: dict) -> dict:
    """Sums time across all saved rows, per model and overall. Computed from
    the data itself (not a single wall-clock timer), so it stays correct
    across resumed/interrupted runs. Flat structure: total_time first, then
    one key per model, in MODELS order."""
    summary = {}
    grand_total = 0.0
    for model in MODELS:
        total = sum(
            (row.get("time") or 0.0)
            for row in results[model].values()
        )
        grand_total += total
        summary[MODEL_TIME_KEYS[model]] = round(total, 3)
    return {"total_time": round(grand_total, 3), **summary}


def print_timing_summary(summary: dict) -> None:
    print("\nTiming summary:")
    print(f"  total_time: {summary['total_time']:.1f}s")
    for model in MODELS:
        key = MODEL_TIME_KEYS[model]
        print(f"  {key}: {summary[key]:.1f}s")

def run_one(model, template, cve):
    prompt = build_prompt(template, cve["description"])
    started = time.perf_counter()
    try:
        raw = call_with_retry(CALLERS[model], prompt, label=model)
        parsed, error = validate(raw)
        elapsed = time.perf_counter() - started
        row = {
            "cve_id": cve["cve_id"],
            "model": model,
            "prompt_condition": CONDITION,
            "description": cve["description"],
            "raw_response": raw,
            "valid": parsed is not None,
            "parsed": parsed,
            "time": round(elapsed, 3),
        }
        if error:  # only include notes when there's actually something to report
            row["notes"] = [error]
        return row
    except Exception as e:
        elapsed = time.perf_counter() - started
        row = {
            "cve_id": cve["cve_id"],
            "model": model,
            "prompt_condition": CONDITION,
            "description": cve["description"],
            "raw_response": "",
            "valid": False,
            "parsed": None,
            "notes": [f"api_error: {e}"],
            "time": round(elapsed, 3),
        }
        return row

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

    completed_total = load_existing_results()
    target = len(eval_cves) * len(MODELS)
    done_count = sum(len(completed_cve_ids(completed_total, m)) for m in MODELS)
    print(f"Resuming: {done_count}/{target} calls already done.\n")

    run_start = time.time()
    fails = {m: 0 for m in MODELS}
    for model in MODELS:
        finished = completed_cve_ids(completed_total, model)
        last = 0.0
        for i, cve in enumerate(eval_cves, 1):
            if cve["cve_id"] in finished:
                continue
            wait = RATE_DELAY[model] - (time.time() - last)
            if wait > 0:
                time.sleep(wait)
            last = time.time()

            call_start = time.time()
            row = run_one(model, template, cve)
            call_elapsed = time.time() - call_start
            completed_total[model][cve["cve_id"]] = row
            save_results(completed_total)

            done_count += 1
            if not row["valid"]:
                fails[model] += 1
                status = f"FAIL ({row['notes']})"
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
    print(f"Total wall-clock time this session: {format_duration(total_elapsed)} "
          f"(includes rate-limit pacing delays)")
    print_timing_summary(compute_timing_summary(completed_total))
    print(f"\nTiming summary is saved in {OUTPUT_PATH} at the top level.")
    print("Log these failure counts in your Decision Log (Day 13-14).")

if __name__ == "__main__":
    main()