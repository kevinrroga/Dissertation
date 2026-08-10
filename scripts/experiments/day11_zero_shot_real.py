"""
Day 6 — Zero-shot prompt test script
=====================================

Purpose
-------
Send the finalized zero-shot extraction prompt to all three models
(GPT-5.5, Claude Sonnet 4.6, DeepSeek V4-Pro) for 5 test CVEs, and check
whether each response is valid JSON matching the required 6-field schema.

All three models are called with reasoning/thinking disabled and
temperature=0 — see decisions_2026-06-27_model-choice-and-decoding-config.md.

NOTE: Gemini was replaced with Claude on 27 June 2026, after persistent
unresolved 503 instability across two different Gemini models (3.1 Pro
Preview and 3.5 Flash) over multiple days. Claude variant is Sonnet 4.6
rather than the Opus tier because Opus 4.7+ deprecated user-settable
sampling parameters at the API level; Sonnet 4.6 still exposes them,
which is required for an identical decoding configuration across all
three providers. See your Decision Log for the full justification.

This is meant to be run on YOUR machine, not in a sandboxed chat
environment — it needs outbound internet access to the model APIs.

Setup
-----
1. Install dependencies:
       pip install openai anthropic google-genai requests python-dotenv

   (google-genai is Google's current Gemini SDK; if you're using a
   different one, swap out call_gemini() accordingly — the rest of
   the script doesn't care how each call_* function is implemented,
   only that it returns a string.)

2. Set your API keys as environment variables (or put them in a
   .env file in this folder):
       export OPENAI_API_KEY="..."
       export GEMINI_API_KEY="..."
       export DEEPSEEK_API_KEY="..."

3. If you already have a locked dataset, point DATASET_PATH at it.
   The script expects a JSON list of records with at least a
   "cve_id" and "description" field. If the file isn't found, it
   falls back to 5 built-in sample CVEs so you can test the script
   itself before your dataset is ready.

4. Run:
       python test_zero_shot_prompt.py

Output
------
- Prints each model's raw response per CVE to the console.
- Writes everything to day6_results.json for your records.
- Prints a final pass/fail summary table per model
  (need >=4/5 valid to hit Day 6's "Done when").
"""

import os
import json
import re
import sys
import time
import csv
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# CONFIG — edit these two lines for your setup
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent.parent
DATASET_PATH = str(_ROOT / "data/datasets/dataset_v1_locked_24jun.json")
NUM_TEST_CVES = 500             # full zero-shot run: all 500 CVEs per model
                                # (override on the command line, e.g. `... 20`,
                                #  for a smaller pilot without editing this file)

# ---------------------------------------------------------------------------
# THE FINALIZED ZERO-SHOT PROMPT (Day 6 deliverable — keep this verbatim
# for your Methodology/Appendix once finalized)
# ---------------------------------------------------------------------------
ZERO_SHOT_TEMPLATE = """You are a cybersecurity analyst assistant. You will be given a single CVE
vulnerability description. Extract the following information based solely
on the text provided. Do not use any outside knowledge about this specific
CVE ID, and do not guess based on the CVE number.

Return your answer as a single valid JSON object with exactly these six
fields, in this order, and nothing else — no explanation, no markdown code
fences, no text before or after the JSON.

{{
  "vulnerability_type": string,
  "attack_vector": one of ["Network", "Adjacent Network", "Local", "Physical", null],
  "affected_component": string,
  "confidentiality_impact": one of ["None", "Low", "High", null],
  "integrity_impact": one of ["None", "Low", "High", null],
  "availability_impact": one of ["None", "Low", "High", null]
}}

Rules:
- vulnerability_type: a short phrase naming the type/category of vulnerability
  (e.g. "SQL Injection", "Buffer Overflow", "Cross-Site Scripting"). Use your
  own judgement based on the description text.
- affected_component: the specific software, product, or component named in
  the description as affected (vendor and product name if both are given).
- attack_vector, confidentiality_impact, integrity_impact, availability_impact:
  choose only from the listed allowed values. Base this strictly on what the
  description says, not on general assumptions about this type of flaw.
- If a field genuinely cannot be determined from the description text, use
  JSON null for that field. Do not invent a value.

CVE Description:
\"\"\"
{description}
\"\"\"
"""

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

# ---------------------------------------------------------------------------
# (Sample CVEs removed — this script runs ONLY on the real locked dataset.
#  If the dataset can't be loaded, the script hard-fails rather than
#  substituting fake data.)
# ---------------------------------------------------------------------------


def load_test_cves(path: str, n: int):
    p = Path(path)
    if not p.exists():
        raise SystemExit(
            f"\n[FATAL] Dataset not found at '{path}'.\n"
            f"        Resolved to: {p.resolve()}\n"
            f"        Current working directory: {Path.cwd()}\n\n"
            f"        This script will NOT fall back to sample CVEs — running a\n"
            f"        real experiment on built-in fake data would silently invalidate\n"
            f"        your results. Fix the path (use an absolute path in DATASET_PATH,\n"
            f"        or run this script from the folder containing the dataset) and\n"
            f"        try again.\n"
        )
    with open(p, "r", encoding="utf-8") as f:
        records = json.load(f)
    if not isinstance(records, list) or len(records) == 0:
        raise SystemExit(
            f"\n[FATAL] '{path}' did not contain a non-empty JSON list of records.\n"
            f"        Refusing to proceed — check the file is your locked dataset.\n"
        )
    if n > len(records):
        print(f"[!] Requested {n} CVEs but dataset has only {len(records)}. Using all {len(records)}.")
        n = len(records)
    subset = records[:n]
    print(f"[i] Loaded {len(subset)} CVEs from {path} (resolved: {p.resolve()}).\n")
    return subset


def strip_code_fences(text: str) -> str:
    """Some models wrap JSON in ```json ... ``` despite instructions not to."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def validate_response(raw_text: str):
    """
    Returns (is_valid: bool, parsed_or_error, notes: list[str])
    """
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

    is_valid = not missing and not extra and len(notes) == (1 if cleaned != raw_text.strip() else 0)
    # is_valid is False if there are any notes other than the fence-stripping one
    real_problems = [n for n in notes if not n.startswith("Response was wrapped")]
    is_valid = len(real_problems) == 0 and not missing and not extra

    return is_valid, parsed, notes


# ---------------------------------------------------------------------------
# Model call functions — each takes a prompt string, returns raw text.
# Fill these in with your actual SDK calls. Stubs raise NotImplementedError
# so you don't silently get fake data if you forget to wire one up.
# ---------------------------------------------------------------------------

def _require_key(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"{name} not found in environment. Check your .env file "
            f"contains a line like: {name}=your-key-here, and that "
            f"it's in the same folder you're running this script from."
        )
    return value


# Substrings that indicate a transient, retry-worthy failure (server
# overload, rate limiting, timeouts) as opposed to a real failure
# (bad auth, bad request, model not found) that retrying won't fix.
RETRYABLE_SIGNALS = (
    "503", "UNAVAILABLE", "overloaded",
    "429", "rate limit", "RateLimit", "Too Many Requests",
    "timeout", "Timeout", "ETIMEDOUT",
    "500", "InternalServerError", "ServiceUnavailable",
)


def call_with_retry(fn, *args, label="model", max_attempts=6,
                     base_backoff=4, max_backoff=60, **kwargs):
    """
    Generic retry-with-exponential-backoff-and-jitter wrapper.

    Used for ALL three providers, not just Gemini — at the scale of
    Day 9's 120-call pilot and Phase 3's 3,000-call full run, GPT-5.5
    and DeepSeek will also occasionally hit rate limits, timeouts, or
    transient 5xx errors. Gemini gets more attempts since its
    preview-tier 503s are more frequent and well-documented; the other
    two get fewer attempts since a real failure there is more likely
    to mean something is actually wrong (e.g. a bad parameter) rather
    than transient load.

    Only retries on errors that look transient (see RETRYABLE_SIGNALS).
    Anything else (auth errors, bad model name, malformed request)
    raises immediately on the first attempt — retrying those just
    wastes time and obscures the real problem.
    """
    import time
    import random

    last_error = None
    backoff = base_backoff

    for attempt in range(1, max_attempts + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            last_error = e
            is_transient = any(sig in str(e) for sig in RETRYABLE_SIGNALS)

            if not is_transient:
                raise  # real failure — don't waste time retrying it

            if attempt < max_attempts:
                wait = min(backoff, max_backoff) + random.uniform(0, 2)
                print(
                    f"    [retry] {label} transient error "
                    f"(attempt {attempt}/{max_attempts}). "
                    f"Waiting {wait:.1f}s before retrying..."
                )
                time.sleep(wait)
                backoff *= 2
            else:
                raise

    raise last_error


def call_gpt5(prompt: str):
    from openai import OpenAI
    client = OpenAI(api_key=_require_key("OPENAI_API_KEY"))
    # Using the floating "gpt-5.5" alias rather than a dated snapshot. Note
    # for Methodology: this means the exact model version may shift if
    # OpenAI updates the alias mid-experiment; record the response's
    # `model` field per call if you want a per-call audit trail.
    response = client.responses.create(
        model="gpt-5.5",
        input=prompt,
        reasoning={"effort": "none"},   # true reasoning-off, available from 5.1+
        temperature=0,                  # greedy decoding for deterministic extraction
    )
    usage = getattr(response, "usage", None)
    usage_dict = {
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    } if usage else {}
    served = getattr(response, "model", None)
    return response.output_text, usage_dict, served


def call_claude(prompt: str) -> str:
    import importlib

    try:
        anthropic = importlib.import_module("anthropic")
    except ImportError as e:
        raise RuntimeError(
            "The anthropic package is required for Claude calls. "
            "Install it with `pip install anthropic`."
        ) from e

    client = anthropic.Anthropic(api_key=_require_key("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model="claude-sonnet-4-6",  # Sonnet 4.6, not Opus: Opus 4.7+ deprecated
                                    # user-settable temperature (400 error on call).
                                    # Sonnet 4.6 still accepts the param, which is
                                    # required to maintain identical decoding
                                    # configuration across all three providers.
                                    # See decisions_2026-06-27_*.md.
        max_tokens=1024,
        temperature=0,              # greedy decoding for deterministic extraction
        messages=[{"role": "user", "content": prompt}],
        # No `thinking` param -> extended thinking stays off (reasoning-off
        # floor for this provider; no per-call flag needed).
        # NOTE: do not also set top_p alongside temperature on 4.x-gen models.
    )
    usage = getattr(response, "usage", None)
    usage_dict = {
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        "total_tokens": (
            getattr(usage, "input_tokens", 0) + getattr(usage, "output_tokens", 0)
        ) if usage else None,
    } if usage else {}
    served = getattr(response, "model", None)
    return response.content[0].text, usage_dict, served


def call_deepseek(prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(
        api_key=_require_key("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )
    # temperature=0 is honoured ONLY because thinking is disabled here; in
    # thinking mode DeepSeek silently ignores temperature.
    response = client.chat.completions.create(
        model="deepseek-v4-pro",  # frontier tier — matches GPT-5.5 / Claude Sonnet 4.6
        messages=[{"role": "user", "content": prompt}],
        temperature=0,            # greedy decoding for deterministic extraction
        extra_body={"thinking": {"type": "disabled"}},  # reasoning off (V4 defaults ON)
    )
    usage = getattr(response, "usage", None)
    usage_dict = {
        "input_tokens": getattr(usage, "prompt_tokens", None),
        "output_tokens": getattr(usage, "completion_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    } if usage else {}
    served = getattr(response, "model", None)
    return response.choices[0].message.content, usage_dict, served


MODELS = {
    "gpt-5.5": {"call_fn": call_gpt5, "max_attempts": 3, "base_backoff": 3},
    "claude-sonnet-4.6": {"call_fn": call_claude, "max_attempts": 3, "base_backoff": 3},
    "deepseek-v4-pro": {"call_fn": call_deepseek, "max_attempts": 3, "base_backoff": 3},
}

# Price per 1,000,000 tokens (input, output), USD. VERIFY against each
# provider's billing dashboard at run time — these are list rates as of
# late June 2026 and DeepSeek's promo rate in particular may have lapsed.
# These are used only to turn measured token usage into an estimated cost;
# your authoritative cost figure for the dissertation is the dashboard.
PRICE_PER_M = {
    "gpt-5.5": (5.00, 30.00),
    "claude-sonnet-4.6": (3.00, 15.00),
    "deepseek-v4-pro": (1.74, 3.48),
}


def load_previous_results(path: Path) -> dict:
    """
    Load results from a prior run, if any, so re-running the script
    doesn't re-pay for calls that already succeeded. Returns {} if no
    prior file exists or it can't be parsed.
    """
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        print(f"[!] Could not read existing {path} — starting fresh.")
        return {}


def already_valid(previous: dict, model_name: str, cve_id: str) -> dict | None:
    """Return the cached entry if this (model, cve_id) already succeeded."""
    for entry in previous.get(model_name, []):
        if entry.get("cve_id") == cve_id and entry.get("valid"):
            return entry
    return None


def save_results(path: Path, results: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def main():
    # Allow overriding the CVE count from the command line:
    #   python zero_shot_instrumented.py        -> uses NUM_TEST_CVES (5)
    #   python zero_shot_instrumented.py 20      -> first 20 CVEs (pilot)
    #   python zero_shot_instrumented.py 500     -> full run
    n_cves = NUM_TEST_CVES
    if len(sys.argv) > 1:
        try:
            n_cves = int(sys.argv[1])
        except ValueError:
            print(f"[!] Ignoring non-integer argument '{sys.argv[1]}'; using {n_cves}.")
    cves = load_test_cves(DATASET_PATH, n_cves)
    out_path = _ROOT / "data/results/zero-shot-real-day11.json"
    previous = load_previous_results(out_path)
    if previous:
        print(f"[i] Found existing {out_path} — will skip CVEs that already passed.\n")

    results = {}        # model -> list of per-CVE result dicts
    pass_counts = {}    # model -> count of valid responses

    for model_name, cfg in MODELS.items():
        call_fn = cfg["call_fn"]
        max_attempts = cfg["max_attempts"]
        base_backoff = cfg["base_backoff"]

        print(f"\n{'='*70}\nMODEL: {model_name}\n{'='*70}")
        results[model_name] = []
        pass_counts[model_name] = 0

        for cve in cves:
            cve_id = cve.get("cve_id", "UNKNOWN")
            description = cve.get("description", "")
            prompt = ZERO_SHOT_TEMPLATE.format(description=description)

            print(f"\n--- {cve_id} ---")

            cached = already_valid(previous, model_name, cve_id)
            if cached:
                print("    [resume] Already passed in a previous run — skipping call.")
                results[model_name].append(cached)
                pass_counts[model_name] += 1
                save_results(out_path, results)
                continue

            try:
                t0 = time.perf_counter()
                raw, usage_dict, served_model = call_with_retry(
                    call_fn, prompt,
                    label=model_name,
                    max_attempts=max_attempts,
                    base_backoff=base_backoff,
                )
                latency_s = time.perf_counter() - t0
            except NotImplementedError:
                print(f"[!] {model_name} call not implemented yet — skipping.")
                results[model_name].append({"cve_id": cve_id, "error": "not implemented"})
                save_results(out_path, results)
                continue
            except RuntimeError as e:
                print(f"[!] Configuration error: {e}")
                results[model_name].append({"cve_id": cve_id, "error": str(e)})
                save_results(out_path, results)
                continue
            except Exception as e:
                print(f"[!] API call failed after retries: {e}")
                results[model_name].append({"cve_id": cve_id, "error": str(e)})
                save_results(out_path, results)
                continue

            print("Raw response:")
            print(raw)
            print(f"    [timing] {latency_s:.2f}s   [usage] {usage_dict}   [served] {served_model}")

            is_valid, parsed_or_error, notes = validate_response(raw)
            if is_valid:
                pass_counts[model_name] += 1
                print("-> VALID")
            else:
                print(f"-> INVALID. Notes: {notes}")

            results[model_name].append({
                "cve_id": cve_id,
                "raw_response": raw,
                "valid": is_valid,
                "parsed": parsed_or_error if is_valid else None,
                "notes": notes,
                "latency_s": round(latency_s, 3),
                "usage": usage_dict,
                "served_model": served_model,
            })
            # Save after every single CVE, not just at the end — a crash
            # on CVE #87 of 120 shouldn't cost you the previous 86 results.
            save_results(out_path, results)

    # ---- Summary: validity, timing, tokens, estimated cost ----
    print(f"\n{'='*70}\nSUMMARY — zero-shot full run\n{'='*70}")
    total = len(cves)

    csv_rows = []
    for model_name in MODELS:
        entries = [e for e in results.get(model_name, []) if "valid" in e]
        n_pass = pass_counts[model_name]
        pct = (100 * n_pass / total) if total else 0
        n_fail = total - n_pass

        latencies = [e["latency_s"] for e in entries if e.get("latency_s") is not None]
        in_tok = sum((e.get("usage") or {}).get("input_tokens") or 0 for e in entries)
        out_tok = sum((e.get("usage") or {}).get("output_tokens") or 0 for e in entries)

        in_price, out_price = PRICE_PER_M.get(model_name, (0, 0))
        est_cost = (in_tok / 1e6) * in_price + (out_tok / 1e6) * out_price

        mean_lat = sum(latencies) / len(latencies) if latencies else 0
        total_lat = sum(latencies)

        print(f"\n{model_name}")
        print(f"  validity     : {n_pass}/{total} valid ({pct:.1f}%)   {n_fail} invalid/failed")
        print(f"  latency      : mean {mean_lat:.2f}s   total {total_lat:.1f}s over {len(latencies)} calls")
        print(f"  tokens       : {in_tok:,} in  +  {out_tok:,} out  =  {in_tok + out_tok:,} total")
        print(f"  est. cost    : ${est_cost:.5f}  (list rate; verify on dashboard)")
        if total > 0 and in_tok:
            # Project the full 500-CVE-per-model run from this sample's mean.
            n_with_usage = len([e for e in entries if e.get("usage")])
            if n_with_usage:
                scale = 500 / n_with_usage
                print(f"  -> projected to 500 CVEs (this model): ${est_cost * scale:.2f}, "
                      f"~{(total_lat * scale)/60:.0f} min sequential")

        csv_rows.append({
            "model": model_name,
            "valid": n_pass,
            "total": total,
            "mean_latency_s": round(mean_lat, 3),
            "total_latency_s": round(total_lat, 1),
            "input_tokens": in_tok,
            "output_tokens": out_tok,
            "est_cost_usd": round(est_cost, 5),
        })

    # Write a flat CSV you can drop straight into your notes / appendix.
    csv_path = _ROOT / "reports/day6_metrics.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
        writer.writeheader()
        writer.writerows(csv_rows)

    grand_cost = sum(r["est_cost_usd"] for r in csv_rows)
    grand_time = sum(r["total_latency_s"] for r in csv_rows)
    print(f"\n{'-'*70}")
    print(f"ALL MODELS: est. ${grand_cost:.4f} total, {grand_time:.0f}s wall time for this {total}-CVE test.")
    print(f"Full results : {out_path.resolve()}")
    print(f"Metrics CSV  : {csv_path.resolve()}")


if __name__ == "__main__":
    main()