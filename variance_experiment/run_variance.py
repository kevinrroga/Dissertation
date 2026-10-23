"""
Variance/stability experiment harness.

What it does:
  For each combination of (CVE × model × prompt_condition × rep), sends the
  same classification prompt and records the output. With temperature=0 and
  reasoning disabled, this measures how much run-to-run variance the hosted
  APIs actually produce despite nominally deterministic settings.

Design:
  50 CVEs × 3 models × 2 conditions × 5 reps = 1,500 calls.
  Logs are written to JSONL (one record per line) immediately after every call.
  On resume the script reads the log, builds the set of completed
  (cve_id, model, condition, rep) tuples, and skips those cells.

CVE selection:
  By default the script reads variance_experiment/cve_ids.json — a plain list
  of CVE ID strings drawn from the locked 500-CVE dataset.  If that file does
  not exist it falls back to the first N CVEs in the dataset (default N=50).
  Pass an integer on the command line to override N for a quick test:
      python run_variance.py 5   # 5 CVEs only, for smoke-testing

Output:
  variance_experiment/results/variance_log.jsonl
    One JSON object per line.  Schema per record:
      cve_id            str
      model             str
      prompt_condition  str  ("zero_shot" | "few_shot")
      rep               int  (1-5)
      timestamp         str  (ISO-8601 UTC)
      latency_s         float
      raw_response      str
      valid             bool
      parsed            dict | null  (the 6-field extraction if valid)
      error             str | null   (message if api call failed)
      notes             list[str] | absent  (validation problems if any)

Install:
    pip install openai anthropic python-dotenv

Run full experiment:
    python run_variance.py

Smoke-test with 5 CVEs:
    python run_variance.py 5
"""

import json
import os
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT / "ultimate_dataset" / "dataset_v1_locked_24jun_with_cwe_names.json"
FEW_SHOT_PROMPT_PATH = ROOT / "few_shot" / "few_shot_prompt.txt"
CVE_IDS_PATH = Path(__file__).resolve().parent / "cve_ids.json"
OUTPUT_DIR = Path(__file__).resolve().parent / "results"
LOG_PATH = OUTPUT_DIR / "variance_log.jsonl"

# ---------------------------------------------------------------------------
# Experiment settings
# ---------------------------------------------------------------------------
DEFAULT_CVE_COUNT = 50
REPS = 5
TEMPERATURE = 0

MODEL_NAMES = [
    "gpt-5.5",
    "claude-sonnet-4.6",
    "deepseek-v4-pro",
]

CONDITIONS = ["zero_shot", "few_shot"]

REQUIRED_KEYS = [
    "vulnerability_type",
    "attack_vector",
    "affected_component",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]

ALLOWED_ATTACK_VECTORS = {"Network", "Adjacent Network", "Local", "Physical", None}
ALLOWED_CIA_VALUES = {"None", "Low", "High", None}

# ---------------------------------------------------------------------------
# Zero-shot prompt (matches zero_shot/zero_shot_final.py exactly)
# ---------------------------------------------------------------------------
ZERO_SHOT_TEMPLATE = """You are a cybersecurity analyst assistant. You will be given a single CVE
vulnerability description.

Your task is to extract and classify triage-relevant vulnerability
information from the supplied CVE description.

Extract vulnerability type and affected component from the description.
For attack vector and CIA impacts, infer the most defensible CVSS-style
category from the exploitation conditions and consequences described.

Use only the information and reasonable implications contained in the
description. Do not use external knowledge about the specific CVE, do not
search for the CVE, and do not use the CVE identifier as evidence.

If the description does not explicitly name a product, file, endpoint, service,
function, or module, but clearly identifies the relevant protocol, feature, or
processing area, return a concise normalized functional description.

The normalized description must remain directly grounded in the text and must
not invent a specific internal implementation component.

Return a single valid JSON object with exactly these six fields, in this order,
and nothing else:

{
  "vulnerability_type": string or null,
  "attack_vector": one of ["Network", "Adjacent Network", "Local", "Physical", null],
  "affected_component": string or null,
  "confidentiality_impact": one of ["None", "Low", "High", null],
  "integrity_impact": one of ["None", "Low", "High", null],
  "availability_impact": one of ["None", "Low", "High", null]
}

Decision rules:

1. vulnerability_type
- Return a short, standard vulnerability category, such as "Command Injection",
  "Path Traversal", "Improper Authorization", "Buffer Overflow", or
  "Cross-Site Scripting".
- Prefer the explicitly stated vulnerability type when one is given.
- If the type is not explicitly named, infer the most defensible category from
  the described weakness and exploitation behaviour.
- Return null only when no defensible vulnerability category can be identified.

2. attack_vector
- "Network": exploitation occurs through a remotely reachable network service
  or protocol and does not require the attacker to share the target's local
  network segment.
- "Adjacent Network": exploitation requires access to the same local, wireless,
  broadcast, or otherwise logically adjacent network.
- "Local": exploitation requires local access, a local account, local code
  execution, or local interaction with the target system.
- "Physical": exploitation requires physical interaction with the device.
- Infer the most defensible NVD/CVSS-style value from the described exploitation
  conditions.
- Return null when the required access path cannot be determined.

3. affected_component
Return the most specific affected product or vulnerable component explicitly
named in the description.
Preserve product names, file names, file paths, functions, endpoints, services,
modules, and version numbers when stated.
When both a product and an internal component are named, include both in one
concise value.
Do not replace a specific named component with a generic phrase such as
"device firmware", "application", or "system".

4. confidentiality_impact, integrity_impact, availability_impact
- Predict the most defensible NVD/CVSS-style impact value from the consequences
  described in the text.
- The correct value may not be explicitly written in the description, so
  reasonable inference is allowed.
- "High": substantial or complete compromise of the relevant security property.
- "Low": limited or partial compromise of the relevant security property.
- "None": the vulnerability does not affect that security property.
- null: the description provides insufficient evidence for a defensible
  prediction.
- Do not assign impacts solely from the general vulnerability type.
- Do not automatically interpret an unmentioned impact as "None".
- An overall publisher severity label is not the same as an individual CIA
  impact value.

Output requirements:
- Return valid JSON only.
- Do not include markdown code fences.
- Do not include explanations or additional text.
- Do not include additional fields.
- Use JSON null, not the string "null".
- Follow the field order shown above.

CVE Description:
\"\"\"
{description}
\"\"\"
"""


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_dataset(cve_ids_filter: list[str] | None, limit: int) -> list[dict]:
    """Return the target CVEs from the locked dataset.

    If cve_ids_filter is provided, return those CVEs (in filter order).
    Otherwise return the first `limit` CVEs from the dataset.
    """
    if not DATASET_PATH.exists():
        raise SystemExit(
            f"\nDataset not found: {DATASET_PATH.resolve()}\n"
            "Check DATASET_PATH near the top of this script."
        )
    with DATASET_PATH.open("r", encoding="utf-8") as f:
        all_cves = json.load(f)
    if not isinstance(all_cves, list) or not all_cves:
        raise SystemExit("The dataset must be a non-empty JSON list.")

    if cve_ids_filter:
        by_id = {c["cve_id"]: c for c in all_cves}
        missing = [cid for cid in cve_ids_filter if cid not in by_id]
        if missing:
            raise SystemExit(
                f"{len(missing)} CVE ID(s) in cve_ids.json not found in the dataset:\n"
                + "\n".join(f"  {cid}" for cid in missing[:10])
                + ("\n  ..." if len(missing) > 10 else "")
            )
        result = [by_id[cid] for cid in cve_ids_filter]
        print(f"Loaded {len(result)} CVEs from cve_ids.json")
        return result

    result = all_cves[:limit]
    print(f"No cve_ids.json found. Using first {len(result)} CVEs from dataset.")
    return result


def load_cve_ids_file() -> list[str] | None:
    """Load variance_experiment/cve_ids.json if it exists."""
    if CVE_IDS_PATH.exists():
        with CVE_IDS_PATH.open("r", encoding="utf-8") as f:
            ids = json.load(f)
        if not isinstance(ids, list):
            raise SystemExit("cve_ids.json must be a JSON list of CVE ID strings.")
        return ids
    return None


def load_few_shot_template() -> str:
    if not FEW_SHOT_PROMPT_PATH.exists():
        raise SystemExit(
            f"Few-shot prompt not found: {FEW_SHOT_PROMPT_PATH.resolve()}\n"
            "Ensure few_shot/few_shot_prompt.txt is present."
        )
    with FEW_SHOT_PROMPT_PATH.open("r", encoding="utf-8") as f:
        template = f.read()
    if "{description}" not in template:
        raise SystemExit(
            f"few_shot_prompt.txt has no {{description}} placeholder. Aborting."
        )
    return template


# ---------------------------------------------------------------------------
# Log I/O — JSONL, one record per line, append-safe
# ---------------------------------------------------------------------------

def load_completed_cells() -> set[tuple]:
    """Scan the log and return the set of (cve_id, model, condition, rep) tuples
    that already have a successful (valid=True) record."""
    completed = set()
    if not LOG_PATH.exists():
        return completed
    with LOG_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip any corrupt line; it won't be re-written
            if rec.get("valid") is True:
                key = (
                    rec.get("cve_id"),
                    rec.get("model"),
                    rec.get("prompt_condition"),
                    rec.get("rep"),
                )
                if all(k is not None for k in key):
                    completed.add(key)
    return completed


def append_record(record: dict) -> None:
    """Append one JSON record to the log file.  Flushes and fsyncs immediately
    so the record survives a crash.  JSONL append is safe because a partial
    final line is just skipped by load_completed_cells()."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


# ---------------------------------------------------------------------------
# Response validation (identical logic to the main experiment scripts)
# ---------------------------------------------------------------------------

def remove_code_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def validate_response(raw_text: str) -> tuple[bool, dict | None, list[str]]:
    problems = []
    cleaned = remove_code_fences(raw_text)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        return False, None, [f"json_parse_error: {e}"]
    if not isinstance(parsed, dict):
        return False, None, ["top_level_not_object"]
    missing = [k for k in REQUIRED_KEYS if k not in parsed]
    extra = [k for k in parsed if k not in REQUIRED_KEYS]
    if missing:
        problems.append(f"missing_keys: {missing}")
    if extra:
        problems.append(f"extra_keys: {extra}")
    if parsed.get("attack_vector") not in ALLOWED_ATTACK_VECTORS:
        problems.append(f"bad_attack_vector: {parsed.get('attack_vector')!r}")
    for field in ("confidentiality_impact", "integrity_impact", "availability_impact"):
        if parsed.get(field) not in ALLOWED_CIA_VALUES:
            problems.append(f"bad_{field}: {parsed.get(field)!r}")
    if problems:
        return False, parsed, problems
    return True, {k: parsed[k] for k in REQUIRED_KEYS}, []


# ---------------------------------------------------------------------------
# API calls — exact same bodies as zero_shot_final.py / few_shot.py
# ---------------------------------------------------------------------------

def require_api_key(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is missing from your .env file.")
    return value


def call_gpt(prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=require_api_key("OPENAI_API_KEY"))
    response = client.responses.create(
        model="gpt-5.5",
        input=prompt,
        reasoning={"effort": "none"},
        temperature=TEMPERATURE,
    )
    return response.output_text


def call_claude(prompt: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=require_api_key("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        temperature=TEMPERATURE,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def call_deepseek(prompt: str) -> str:
    from openai import OpenAI
    client = OpenAI(
        api_key=require_api_key("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )
    response = client.chat.completions.create(
        model="deepseek-v4-pro",
        messages=[{"role": "user", "content": prompt}],
        temperature=TEMPERATURE,
        extra_body={"thinking": {"type": "disabled"}},
    )
    return response.choices[0].message.content


MODEL_CALLS = {
    "gpt-5.5": call_gpt,
    "claude-sonnet-4.6": call_claude,
    "deepseek-v4-pro": call_deepseek,
}

RETRYABLE_SIGNALS = (
    "429", "rate limit", "ratelimit", "too many requests",
    "timeout", "etimedout",
    "500", "503", "overloaded", "service unavailable", "internalservererror",
)


def call_with_retry(call_fn, prompt: str, label: str, max_attempts: int = 3):
    backoff = 3.0
    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            return call_fn(prompt)
        except Exception as e:
            last_error = e
            msg = str(e).lower()
            if not any(sig in msg for sig in RETRYABLE_SIGNALS):
                raise
            if attempt < max_attempts:
                wait = min(backoff, 60.0) + random.uniform(0, 2)
                print(
                    f"    [retry] {label} transient error "
                    f"(attempt {attempt}/{max_attempts}); waiting {wait:.1f}s — {e}"
                )
                time.sleep(wait)
                backoff *= 2
            else:
                raise
    raise last_error  # unreachable, but satisfies type checkers


# ---------------------------------------------------------------------------
# Progress display helpers
# ---------------------------------------------------------------------------

def total_cells(n_cves: int) -> int:
    return n_cves * len(MODEL_NAMES) * len(CONDITIONS) * REPS


def format_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# ---------------------------------------------------------------------------
# Main experiment loop
# ---------------------------------------------------------------------------

def run_experiment(cves: list[dict], prompt_templates: dict[str, str]) -> None:
    """
    Loop order: model → condition → CVE → rep.
    This keeps the terminal output grouped by model and condition, making it
    easy to spot a model that is consistently slower or producing errors.
    """
    completed = load_completed_cells()
    n_total = total_cells(len(cves))
    n_done_start = len(completed)
    print(
        f"Resuming: {n_done_start}/{n_total} cells already done "
        f"({n_total - n_done_start} remaining).\n"
    )

    done_this_session = 0
    session_start = time.time()

    for model in MODEL_NAMES:
        call_fn = MODEL_CALLS[model]

        for condition in CONDITIONS:
            template = prompt_templates[condition]
            print("=" * 72)
            print(f"MODEL: {model}  |  CONDITION: {condition}")
            print("=" * 72)

            for cve in cves:
                cve_id = cve.get("cve_id", "UNKNOWN")
                description = cve.get("description", "")
                prompt = template.replace("{description}", description)

                for rep in range(1, REPS + 1):
                    cell_key = (cve_id, model, condition, rep)

                    if cell_key in completed:
                        continue  # already done

                    n_done_total = n_done_start + done_this_session
                    pct = (n_done_total / n_total) * 100
                    print(
                        f"\n[{model}|{condition}] {cve_id}  rep {rep}/{REPS}  "
                        f"(total {n_done_total}/{n_total}, {pct:.1f}%)"
                    )

                    if not description:
                        record = _make_error_record(
                            cve_id, model, condition, rep,
                            error="missing_description", latency_s=0.0, raw="",
                        )
                        append_record(record)
                        done_this_session += 1
                        continue

                    started = time.perf_counter()
                    try:
                        raw = call_with_retry(call_fn, prompt, label=f"{model}/{condition}")
                        latency_s = round(time.perf_counter() - started, 3)
                        valid, parsed, notes = validate_response(raw)

                        status = "VALID" if valid else "INVALID"
                        print(f"  {status}  latency={latency_s}s")
                        if notes:
                            print(f"  notes: {'; '.join(notes)}")

                        record = {
                            "cve_id": cve_id,
                            "model": model,
                            "prompt_condition": condition,
                            "rep": rep,
                            "timestamp": _utc_now(),
                            "latency_s": latency_s,
                            "raw_response": raw,
                            "valid": valid,
                            "parsed": parsed,
                            "error": None,
                        }
                        if notes:
                            record["notes"] = notes

                    except Exception as e:
                        latency_s = round(time.perf_counter() - started, 3)
                        print(f"  FAILED after {latency_s}s: {e}")
                        record = _make_error_record(
                            cve_id, model, condition, rep,
                            error=str(e), latency_s=latency_s, raw="",
                        )

                    append_record(record)
                    completed.add(cell_key)
                    done_this_session += 1

                    elapsed = time.time() - session_start
                    print(f"  session elapsed: {format_duration(elapsed)}")

    print("\n" + "=" * 72)
    print("EXPERIMENT COMPLETE")
    n_final = n_done_start + done_this_session
    print(f"Total cells done: {n_final}/{n_total}")
    print(f"Session wall-clock time: {format_duration(time.time() - session_start)}")
    print(f"Log: {LOG_PATH.resolve()}")
    print("=" * 72)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_error_record(
    cve_id: str, model: str, condition: str, rep: int,
    error: str, latency_s: float, raw: str,
) -> dict:
    return {
        "cve_id": cve_id,
        "model": model,
        "prompt_condition": condition,
        "rep": rep,
        "timestamp": _utc_now(),
        "latency_s": latency_s,
        "raw_response": raw,
        "valid": False,
        "parsed": None,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    limit = DEFAULT_CVE_COUNT
    if len(sys.argv) > 1:
        try:
            limit = int(sys.argv[1])
        except ValueError:
            raise SystemExit("Optional argument must be an integer CVE count.")
        if limit < 1:
            raise SystemExit("CVE count must be at least 1.")

    cve_ids_filter = load_cve_ids_file()
    cves = load_dataset(cve_ids_filter, limit)

    few_shot_template = load_few_shot_template()
    prompt_templates = {
        "zero_shot": ZERO_SHOT_TEMPLATE,
        "few_shot": few_shot_template,
    }

    print(f"\nVariance experiment: {len(cves)} CVEs × {len(MODEL_NAMES)} models "
          f"× {len(CONDITIONS)} conditions × {REPS} reps "
          f"= {total_cells(len(cves))} total calls")
    print(f"Log path: {LOG_PATH.resolve()}\n")

    run_experiment(cves, prompt_templates)


if __name__ == "__main__":
    main()
