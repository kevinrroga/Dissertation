"""
Day 9 — Pilot run harness
=========================================================================
20 CVEs x {zero-shot, few-shot} x 3 models = 120 calls.

This is the Day 9 deliverable. It reuses, verbatim, the model-call,
retry, validation, and incremental-save machinery you finalised in
test_zero_shot_prompt.py (Day 6) and test_few_shot_prompt.py (Day 7).
The ONLY new logic here is:
  1. A deterministic 20-CVE sampler that EXCLUDES the three few-shot
     exemplars (so few-shot can't "succeed" on a CVE whose answer is
     already in its own prompt).
  2. A two-condition runner (zero-shot AND few-shot in one pass).
  3. A failure-rate reporter that prints a per-model, per-condition
     mechanical-failure table and a PROCEED / FIX-AND-REPILOT verdict
     against a hard threshold.
  4. A human-inspection file pairing each extraction next to its CVE
     description, so you can eyeball plausibility (the part the
     failure rate CANNOT tell you).

WHAT "FAILURE" MEANS HERE (mechanical only):
  - API error after retries, OR
  - response does not parse as JSON, OR
  - parses but is missing a required key / has an out-of-enum value.
A semantically WRONG-but-well-formed answer is NOT a failure at this
stage. That is a Day 18 scoring concern. Conflating the two would
corrupt both. The inspection file is where you catch bad-but-valid
output by eye.

RUN THIS ON YOUR MACHINE (needs outbound access to the model APIs):

    pip install openai anthropic requests python-dotenv
    # set OPENAI_API_KEY, ANTHROPIC_API_KEY, DEEPSEEK_API_KEY
    python run_day9_pilot.py

Outputs (written next to this script):
  - day9_pilot_raw.json            every call's raw response + validity
  - day9_pilot_failures.csv        per-model x condition failure table
  - day9_pilot_inspection.txt      extractions laid out for manual review
  - day9_pilot_sample_cves.json    the exact 20 CVEs used (reproducibility)
"""

import os
import csv
import json
import re
import random
from pathlib import Path
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

# ===========================================================================
# CONFIG
# ===========================================================================
_ROOT = Path(__file__).resolve().parent.parent.parent
DATASET_PATH = str(_ROOT / "data/datasets/dataset_v1_locked_24jun.json")
NUM_PILOT_CVES = 20            # Day 9: 20 CVEs (not 5)
SAMPLE_SEED = 42              # deterministic -> the pilot is reproducible

# The three few-shot exemplars, drawn from inside the 500. They MUST be
# excluded from the pilot sample so few-shot is never scored on a CVE
# whose gold answer sits in its own prompt. (Day 7 decision: n=497.)
FEWSHOT_EXEMPLAR_IDS = {"CVE-2026-6073", "CVE-2026-47307", "CVE-2026-44409"}

# Day 9 "Done when" bar, made concrete so the verdict isn't hand-waved:
#   mechanical failure rate per (model, condition) must be <= this.
# Above it -> FIX-AND-REPILOT, do not scale to the full 3,000.
MAX_ACCEPTABLE_FAILURE_RATE = 0.05   # 5%

# How many extractions to drop into the manual-inspection file per
# (model, condition). The roadmap says inspect ~15 total; this gives you
# generous coverage to eyeball plausibility.
INSPECT_PER_CELL = 5

# ===========================================================================
# SCHEMA + VALIDATION (identical to Day 6/7 — kept in sync deliberately)
# ===========================================================================
REQUIRED_KEYS = [
    "vulnerability_type",
    "attack_vector",
    "affected_component",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]
ALLOWED_AV = {"Network", "Adjacent Network", "Local", "Physical", None}
ALLOWED_CIA = {"None", "Low", "High", None}


def strip_code_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def validate_response(raw_text: str):
    """Returns (is_valid, parsed_or_error, notes). Mechanical validity only."""
    notes = []
    cleaned = strip_code_fences(raw_text)
    if cleaned != raw_text.strip():
        notes.append("Response was wrapped in markdown code fences (stripped).")

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        return False, f"JSON parse error: {e}", notes

    if not isinstance(parsed, dict):
        return False, "Top-level JSON is not an object.", notes

    missing = [k for k in REQUIRED_KEYS if k not in parsed]
    extra = [k for k in parsed.keys() if k not in REQUIRED_KEYS]
    if missing:
        notes.append(f"Missing keys: {missing}")
    if extra:
        notes.append(f"Unexpected extra keys: {extra}")

    if parsed.get("attack_vector") not in ALLOWED_AV:
        notes.append(f"attack_vector '{parsed.get('attack_vector')}' not in allowed enum.")
    for field in ("confidentiality_impact", "integrity_impact", "availability_impact"):
        if parsed.get(field) not in ALLOWED_CIA:
            notes.append(f"{field} '{parsed.get(field)}' not in allowed enum.")

    real_problems = [n for n in notes if not n.startswith("Response was wrapped")]
    is_valid = len(real_problems) == 0 and not missing and not extra
    return is_valid, parsed, notes


# ===========================================================================
# PROMPTS — imported verbatim from your Day 6 / Day 7 scripts so there is a
# SINGLE source of truth. If those files sit next to this one, we import the
# templates directly rather than copy-pasting (copy-paste drift is how the
# zero-shot/few-shot comparison silently stops being clean).
# ===========================================================================
try:
    import importlib.util

    def _load_template(filename, attr):
        spec = importlib.util.spec_from_file_location(filename.replace(".py", ""), filename)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return getattr(mod, attr)

    ZERO_SHOT_TEMPLATE = _load_template("test_zero_shot_prompt.py", "ZERO_SHOT_TEMPLATE")
    FEW_SHOT_TEMPLATE = _load_template("test_few_shot_prompt.py", "FEW_SHOT_TEMPLATE")
    print("[i] Imported prompt templates from your Day 6/7 scripts (single source of truth).")
except Exception as e:
    raise SystemExit(
        f"[FATAL] Could not import prompt templates from your Day 6/7 scripts: {e}\n"
        f"        Make sure test_zero_shot_prompt.py and test_few_shot_prompt.py\n"
        f"        sit in the same folder as this harness. The harness deliberately\n"
        f"        does NOT keep its own copy of the prompts, so the pilot uses the\n"
        f"        exact finalised wording and your conditions stay comparable."
    )

CONDITIONS = {
    "zero_shot": ZERO_SHOT_TEMPLATE,
    "few_shot": FEW_SHOT_TEMPLATE,
}

# ===========================================================================
# MODEL CALLS + RETRY (identical to Day 6/7)
# ===========================================================================
def _require_key(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} not found in environment. Add it to your .env file as "
            f"{name}=your-key-here, in the folder you run this from."
        )
    return value


RETRYABLE_SIGNALS = (
    "503", "UNAVAILABLE", "overloaded",
    "429", "rate limit", "RateLimit", "Too Many Requests",
    "timeout", "Timeout", "ETIMEDOUT",
    "500", "InternalServerError", "ServiceUnavailable",
)


def call_with_retry(fn, *args, label="model", max_attempts=3,
                    base_backoff=3, max_backoff=60, **kwargs):
    import time
    last_error = None
    backoff = base_backoff
    for attempt in range(1, max_attempts + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            last_error = e
            if not any(sig in str(e) for sig in RETRYABLE_SIGNALS):
                raise
            if attempt < max_attempts:
                wait = min(backoff, max_backoff) + random.uniform(0, 2)
                print(f"    [retry] {label} transient error "
                      f"(attempt {attempt}/{max_attempts}). Waiting {wait:.1f}s...")
                time.sleep(wait)
                backoff *= 2
            else:
                raise
    raise last_error


def call_gpt5(prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=_require_key("OPENAI_API_KEY"))
    response = client.responses.create(
        model="gpt-5.5",
        input=prompt,
        reasoning={"effort": "none"},
        temperature=0,
    )
    return response.output_text


def call_claude(prompt: str) -> str:
    import importlib
    anthropic = importlib.import_module("anthropic")
    client = anthropic.Anthropic(api_key=_require_key("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        temperature=0,
        messages=[{"role": "user", "content": prompt}],
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
        temperature=0,
        extra_body={"thinking": {"type": "disabled"}},
    )
    return response.choices[0].message.content


MODELS = {
    "gpt-5.5": {"call_fn": call_gpt5, "max_attempts": 3, "base_backoff": 3},
    "claude-sonnet-4.6": {"call_fn": call_claude, "max_attempts": 3, "base_backoff": 3},
    "deepseek-v4-pro": {"call_fn": call_deepseek, "max_attempts": 3, "base_backoff": 3},
}


# ===========================================================================
# SAMPLING — deterministic, exemplar-excluded
# ===========================================================================
def load_pilot_cves(path: str, n: int, seed: int):
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"[FATAL] Dataset not found at '{path}'.")
    with open(p, "r", encoding="utf-8") as f:
        records = json.load(f)
    if not isinstance(records, list) or not records:
        raise SystemExit(f"[FATAL] '{path}' is not a non-empty JSON list.")

    eligible = [r for r in records if r.get("cve_id") not in FEWSHOT_EXEMPLAR_IDS]
    excluded = len(records) - len(eligible)
    if len(eligible) < n:
        raise SystemExit(f"[FATAL] Only {len(eligible)} eligible CVEs, need {n}.")

    rng = random.Random(seed)
    sample = rng.sample(eligible, n)
    print(f"[i] Sampled {n} CVEs (seed={seed}); excluded {excluded} few-shot exemplar(s).")
    return sample


# ===========================================================================
# PERSISTENCE (incremental + resume)
# ===========================================================================
def load_previous(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        print(f"[!] Could not read existing {path} — starting fresh.")
        return {}


def cached_entry(previous, cell_key, cve_id):
    for entry in previous.get(cell_key, []):
        if entry.get("cve_id") == cve_id and entry.get("valid"):
            return entry
    return None


def save_json(path: Path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


# ===========================================================================
# REPORTING
# ===========================================================================
def write_failure_csv(path: Path, results: dict, n_per_cell: int):
    rows = []
    for cell_key, entries in results.items():
        model, condition = cell_key.split("|", 1)
        attempted = len(entries)
        failures = sum(1 for e in entries if not e.get("valid"))
        rate = failures / attempted if attempted else 0.0
        verdict = "PROCEED" if rate <= MAX_ACCEPTABLE_FAILURE_RATE else "FIX-AND-REPILOT"
        rows.append({
            "model": model,
            "condition": condition,
            "attempted": attempted,
            "failures": failures,
            "failure_rate": f"{rate:.1%}",
            "verdict": verdict,
        })
    rows.sort(key=lambda r: (r["model"], r["condition"]))
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["model", "condition", "attempted",
                                          "failures", "failure_rate", "verdict"])
        w.writeheader()
        w.writerows(rows)
    return rows


def write_inspection_file(path: Path, results: dict, cve_by_id: dict, n: int):
    lines = []
    lines.append("DAY 9 PILOT — MANUAL SANITY INSPECTION")
    lines.append("=" * 72)
    lines.append("Failure rate proves the pipeline is mechanically sound. It does")
    lines.append("NOT prove the extractions are GOOD. Read these by eye: does the")
    lines.append("attack_vector / component / impact actually match the description?")
    lines.append("A model can return flawless JSON full of nonsense.")
    lines.append("")
    lines.append("Note: ground truth below uses NVD's UPPER_CASE enum (e.g. NETWORK,")
    lines.append("HIGH); the model is prompted for Title Case (Network, High). That")
    lines.append("casing gap is handled at Day 18 scoring, not here — don't mistake")
    lines.append("it for a wrong answer during inspection.")
    lines.append("=" * 72)
    lines.append("")

    for cell_key, entries in results.items():
        model, condition = cell_key.split("|", 1)
        lines.append("")
        lines.append("#" * 72)
        lines.append(f"# {model}  |  {condition}")
        lines.append("#" * 72)
        shown = 0
        # Prefer to surface any invalids first (they're the most informative),
        # then fill up to n with valids.
        ordered = sorted(entries, key=lambda e: e.get("valid", False))
        for e in ordered:
            if shown >= n:
                break
            cve_id = e.get("cve_id", "?")
            gt = cve_by_id.get(cve_id, {})
            lines.append("")
            lines.append(f"--- {cve_id}  [{'VALID' if e.get('valid') else 'INVALID'}] ---")
            lines.append("DESCRIPTION:")
            lines.append(f"  {gt.get('description', '(not found)')}")
            lines.append("GROUND TRUTH (NVD):")
            lines.append(f"  type(CWE)={gt.get('cwe_ids')}  AV={gt.get('attack_vector')}  "
                         f"C={gt.get('confidentiality_impact')} "
                         f"I={gt.get('integrity_impact')} "
                         f"A={gt.get('availability_impact')}")
            lines.append(f"  component={gt.get('affected_components')}")
            lines.append("MODEL EXTRACTION:")
            parsed = e.get("parsed")
            if parsed:
                lines.append(f"  type={parsed.get('vulnerability_type')!r}  "
                             f"AV={parsed.get('attack_vector')!r}  "
                             f"C={parsed.get('confidentiality_impact')!r} "
                             f"I={parsed.get('integrity_impact')!r} "
                             f"A={parsed.get('availability_impact')!r}")
                lines.append(f"  component={parsed.get('affected_component')!r}")
            else:
                lines.append(f"  (no valid parse) notes={e.get('notes')}")
                if e.get("raw_response"):
                    lines.append(f"  raw={e['raw_response'][:300]}")
            shown += 1
    path.write_text("\n".join(lines), encoding="utf-8")


# ===========================================================================
# MAIN
# ===========================================================================
def main():
    cves = load_pilot_cves(DATASET_PATH, NUM_PILOT_CVES, SAMPLE_SEED)
    cve_by_id = {c["cve_id"]: c for c in cves}

    out_raw = _ROOT / "data/results/day9_pilot_raw.json"
    out_csv = _ROOT / "reports/day9_pilot_failures.csv"
    out_inspect = _ROOT / "reports/day9_pilot_inspection.txt"
    out_sample = _ROOT / "data/results/day9_pilot_sample_cves.json"
    save_json(out_sample, cves)

    previous = load_previous(out_raw)
    if previous:
        print(f"[i] Found existing {out_raw} — completed calls will be skipped.\n")

    results = {}  # "model|condition" -> list of per-CVE dicts

    for model_name, cfg in MODELS.items():
        for cond_name, template in CONDITIONS.items():
            cell_key = f"{model_name}|{cond_name}"
            results[cell_key] = []
            print(f"\n{'='*70}\n{model_name}  |  {cond_name}\n{'='*70}")

            for cve in cves:
                cve_id = cve.get("cve_id", "UNKNOWN")
                description = cve.get("description", "")
                prompt = template.format(description=description)

                cached = cached_entry(previous, cell_key, cve_id)
                if cached:
                    print(f"--- {cve_id}: [resume] already passed, skipping call.")
                    results[cell_key].append(cached)
                    save_json(out_raw, results)
                    continue

                print(f"--- {cve_id}")
                try:
                    raw = call_with_retry(
                        cfg["call_fn"], prompt,
                        label=cell_key,
                        max_attempts=cfg["max_attempts"],
                        base_backoff=cfg["base_backoff"],
                    )
                except Exception as e:
                    print(f"    [!] call failed: {e}")
                    results[cell_key].append({
                        "cve_id": cve_id, "valid": False,
                        "raw_response": None, "parsed": None,
                        "notes": [f"API/config failure: {e}"],
                    })
                    save_json(out_raw, results)
                    continue

                is_valid, parsed_or_err, notes = validate_response(raw)
                print("    -> VALID" if is_valid else f"    -> INVALID {notes}")
                results[cell_key].append({
                    "cve_id": cve_id,
                    "raw_response": raw,
                    "valid": is_valid,
                    "parsed": parsed_or_err if is_valid else None,
                    "notes": notes,
                })
                save_json(out_raw, results)

    # ---- Reports ----
    rows = write_failure_csv(out_csv, results, NUM_PILOT_CVES)
    write_inspection_file(out_inspect, results, cve_by_id, INSPECT_PER_CELL)

    print(f"\n{'='*70}\nDAY 9 PILOT — FAILURE RATES "
          f"(threshold {MAX_ACCEPTABLE_FAILURE_RATE:.0%})\n{'='*70}")
    print(f"{'model':20s} {'condition':11s} {'fail':>5s} {'rate':>7s}  verdict")
    print("-" * 60)
    worst = "PROCEED"
    for r in rows:
        print(f"{r['model']:20s} {r['condition']:11s} "
              f"{r['failures']:>2d}/{r['attempted']:<2d} "
              f"{r['failure_rate']:>7s}  {r['verdict']}")
        if r["verdict"] != "PROCEED":
            worst = "FIX-AND-REPILOT"

    print("-" * 60)
    print(f"\nOVERALL VERDICT: {worst}")
    if worst == "PROCEED":
        print("All cells within threshold. BUT this only confirms mechanical")
        print("soundness — now open day9_pilot_inspection.txt and read the")
        print("extractions before you commit budget to the full 3,000-call run.")
    else:
        print("At least one cell exceeded the failure threshold. Per the roadmap:")
        print("iterate the prompt and RE-PILOT. Do not scale to 500 to hit a date.")

    print(f"\nWritten:\n  {out_raw}\n  {out_csv}\n  {out_inspect}\n  {out_sample}")
    print(f"\nFinished: {datetime.now(timezone.utc).isoformat()}")


if __name__ == "__main__":
    main()