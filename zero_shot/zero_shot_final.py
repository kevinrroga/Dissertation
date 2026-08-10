"""
Final zero-shot experiment script.

What it does:
- Loads CVEs from the locked dataset.
- Sends the corrected zero-shot prompt to three models.
- Validates the six-field JSON response.
- Prints live progress in the terminal.
- Saves after every CVE so the run can resume safely.
- Writes results to: zero_shot/output_of_zero-shot.json

Install:
    pip install openai anthropic python-dotenv

Run all 500 CVEs:
    python zero_shot_final.py

Run a smaller test:
    python zero_shot_final.py 5
"""

import json
import os
import random
import re
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Paths and experiment settings
ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT / "data" / "datasets" / "dataset_v1_locked_24jun_with_cwe_names.json"
OUTPUT_PATH = ROOT / "zero_shot" / "output_of_zero-shot.json"
DEFAULT_CVE_COUNT = 500
TEMPERATURE = 0

MODEL_NAMES = [
    "gpt-5.5",
    "claude-sonnet-4.6",
    "deepseek-v4-pro",
]

# Short keys used for the flattened timing summary at the top level.
MODEL_TIME_KEYS = {
    "gpt-5.5": "gpt_time",
    "claude-sonnet-4.6": "claude_time",
    "deepseek-v4-pro": "deepseek_time",
}

REQUIRED_KEYS = [
    "vulnerability_type",
    "attack_vector",
    "affected_component",
    "confidentiality_impact",
    "integrity_impact",
    "availability_impact",
]

ALLOWED_ATTACK_VECTORS = {
    "Network",
    "Adjacent Network",
    "Local",
    "Physical",
    None,
}
ALLOWED_CIA_VALUES = {"None", "Low", "High", None}


# Corrected zero-shot prompt
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

{{
  "vulnerability_type": string or null,
  "attack_vector": one of ["Network", "Adjacent Network", "Local", "Physical", null],
  "affected_component": string or null,
  "confidentiality_impact": one of ["None", "Low", "High", null],
  "integrity_impact": one of ["None", "Low", "High", null],
  "availability_impact": one of ["None", "Low", "High", null]
}}

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


def load_dataset(limit: int) -> list[dict]:
    """Load the first `limit` CVEs from the locked dataset."""
    if not DATASET_PATH.exists():
        raise SystemExit(
            f"\nDataset not found:\n{DATASET_PATH.resolve()}\n"
            "Check DATASET_PATH near the top of this script."
        )

    with DATASET_PATH.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list) or not records:
        raise SystemExit("The dataset must be a non-empty JSON list.")

    limit = min(limit, len(records))
    print(f"Loaded {limit} CVEs from {DATASET_PATH.resolve()}")
    return records[:limit]


def load_existing_results() -> dict:
    """Load an earlier partial run so successful calls are not repeated.

    Internal working structure is {model: {cve_id: row}}, not a list -- a
    retry now OVERWRITES the previous row for that CVE instead of appending
    a second one. This is the fix for the duplicate-row issue seen after the
    claude-sonnet-4.6 credit-exhaustion incident (540 rows for 500 CVEs:
    500 valid + 40 orphaned failures that were never cleaned up on resume).
    """
    if not OUTPUT_PATH.exists():
        return {model: {} for model in MODEL_NAMES}

    try:
        with OUTPUT_PATH.open("r", encoding="utf-8") as file:
            saved = json.load(file)
    except (json.JSONDecodeError, OSError):
        print("Existing output could not be read. Starting a new result file.")
        return {model: {} for model in MODEL_NAMES}

    results = {model: {} for model in MODEL_NAMES}
    for model in MODEL_NAMES:
        for row in saved.get(model, []):  # only known model keys are read; timing keys at the top level are ignored here
            cid = row.get("cve_id")
            if cid:
                results[model][cid] = row

    print(f"Resuming from existing file: {OUTPUT_PATH.resolve()}")
    return results


def compute_timing_summary(results: dict) -> dict:
    """Sums time across all saved rows, per model and overall. Computed from
    the data itself (not a single wall-clock timer), so it stays correct
    across resumed/interrupted runs. Flat structure: total_time first, then
    one key per model, in MODEL_NAMES order."""
    summary = {}
    grand_total = 0.0
    for model in MODEL_NAMES:
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
    for model in MODEL_NAMES:
        key = MODEL_TIME_KEYS[model]
        print(f"  {key}: {summary[key]:.1f}s")


def save_results(results: dict) -> None:
    """Save immediately after each CVE. Serializes to {model: [row,...]} plus
    the timing keys (total_time, gpt_time, claude_time, deepseek_time)
    sitting directly at the top level -- no wrapper key."""
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    to_save = {model: list(results[model].values()) for model in MODEL_NAMES}
    to_save.update(compute_timing_summary(results))
    tmp_path = OUTPUT_PATH.with_suffix(OUTPUT_PATH.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as file:
        json.dump(to_save, file, indent=2, ensure_ascii=False)
        file.flush()
        os.fsync(file.fileno())
    tmp_path.replace(OUTPUT_PATH)


def completed_cve_ids(results: dict, model_name: str) -> set[str]:
    """Return CVEs already successfully processed for one model. Only a
    genuine success (valid is True) counts as done -- a previously failed
    CVE stays eligible for retry on resume."""
    return {
        cid for cid, row in results[model_name].items()
        if row.get("valid") is True
    }


def remove_code_fences(text: str) -> str:
    """Remove ```json fences if a model adds them."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def validate_response(raw_text: str) -> tuple[bool, dict | None, list[str]]:
    """Check JSON format, exact keys, and allowed categorical values."""
    problems = []
    cleaned = remove_code_fences(raw_text)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as error:
        return False, None, [f"JSON parse error: {error}"]

    if not isinstance(parsed, dict):
        return False, None, ["Top-level response is not a JSON object."]

    missing = [key for key in REQUIRED_KEYS if key not in parsed]
    extra = [key for key in parsed if key not in REQUIRED_KEYS]

    if missing:
        problems.append(f"Missing keys: {missing}")
    if extra:
        problems.append(f"Extra keys: {extra}")

    if parsed.get("attack_vector") not in ALLOWED_ATTACK_VECTORS:
        problems.append(f"Invalid attack_vector: {parsed.get('attack_vector')!r}")

    for field in (
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
    ):
        if parsed.get(field) not in ALLOWED_CIA_VALUES:
            problems.append(f"Invalid {field}: {parsed.get(field)!r}")

    if problems:
        return False, parsed, problems

    ordered = {key: parsed[key] for key in REQUIRED_KEYS}
    return True, ordered, []


def require_api_key(name: str) -> str:
    """Read one API key from the .env file or environment."""
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} is missing from your .env file.")
    return value


def call_gpt(prompt: str) -> str:
    """Call GPT-5.5 with reasoning disabled."""
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
    """Call Claude Sonnet 4.6."""
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
    """Call DeepSeek with thinking disabled."""
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


def call_with_retry(call_function, prompt: str, model_name: str):
    """Retry temporary API failures up to three times."""
    for attempt in range(1, 4):
        try:
            return call_function(prompt)
        except Exception as error:
            message = str(error).lower()
            temporary = any(
                signal in message
                for signal in (
                    "429",
                    "rate limit",
                    "timeout",
                    "500",
                    "503",
                    "overloaded",
                    "service unavailable",
                )
            )

            if not temporary or attempt == 3:
                raise

            wait_seconds = (2 ** attempt) + random.uniform(0, 1)
            print(
                f"  Temporary {model_name} error. "
                f"Retry {attempt}/3 in {wait_seconds:.1f}s."
            )
            time.sleep(wait_seconds)


def run_experiment(number_of_cves: int) -> None:
    cves = load_dataset(number_of_cves)
    results = load_existing_results()

    total_models = len(MODEL_NAMES)
    total_cves = len(cves)

    for model_number, model_name in enumerate(MODEL_NAMES, start=1):
        print("\n" + "=" * 72)
        print(f"MODEL {model_number}/{total_models}: {model_name}")
        print("=" * 72)

        results.setdefault(model_name, {})
        finished = completed_cve_ids(results, model_name)
        call_function = MODEL_CALLS[model_name]

        for cve_number, cve in enumerate(cves, start=1):
            cve_id = cve.get("cve_id", "UNKNOWN")
            description = cve.get("description", "")
            percentage = (cve_number / total_cves) * 100

            print(
                f"\n[{model_name}] "
                f"CVE {cve_number}/{total_cves} "
                f"({percentage:.1f}%) - {cve_id}"
            )

            if cve_id in finished:
                print("  Already completed. Skipping.")
                continue

            if not description:
                print("  Missing description. Saving as failed.")
                results[model_name][cve_id] = {
                    "cve_id": cve_id,
                    "valid": False,
                    "error": "Missing description",
                }
                save_results(results)
                continue

            prompt = ZERO_SHOT_TEMPLATE.format(description=description)
            started = time.perf_counter()

            try:
                raw = call_with_retry(
                    call_function,
                    prompt,
                    model_name,
                )
                elapsed = time.perf_counter() - started
                valid, parsed, notes = validate_response(raw)

                print(f"  Time: {elapsed:.2f}s")
                print(f"  Status: {'VALID' if valid else 'INVALID'}")
                print(f"  Result: {json.dumps(parsed, ensure_ascii=False)}")

                if notes:
                    print(f"  Problems: {'; '.join(notes)}")

                row = {
                    "cve_id": cve_id,
                    "prompt_condition": "zero_shot",
                    "model": model_name,
                    "description": description,
                    "raw_response": raw,
                    "valid": valid,
                    "parsed": parsed,
                    "time": round(elapsed, 3),
                }
                if notes:  # only include notes when there's actually something to report
                    row["notes"] = notes

            except Exception as error:
                elapsed = time.perf_counter() - started
                print(f"  FAILED after {elapsed:.2f}s: {error}")
                row = {
                    "cve_id": cve_id,
                    "prompt_condition": "zero_shot",
                    "model": model_name,
                    "description": description,
                    "valid": False,
                    "error": str(error),
                    "time": round(elapsed, 3),
                }

            results[model_name][cve_id] = row
            save_results(results)

        valid_count = sum(
            1 for row in results[model_name].values() if row.get("valid") is True
        )
        print(
            f"\nCompleted {model_name}: "
            f"{valid_count}/{total_cves} valid responses."
        )

    print("\n" + "=" * 72)
    print("EXPERIMENT FINISHED")
    print_timing_summary(compute_timing_summary(results))
    print(f"\nResults saved to:\n{OUTPUT_PATH.resolve()}")
    print("=" * 72)


def read_requested_count() -> int:
    """Read an optional CVE count from the command line."""
    if len(sys.argv) == 1:
        return DEFAULT_CVE_COUNT

    try:
        requested = int(sys.argv[1])
    except ValueError:
        raise SystemExit("The optional CVE count must be an integer.")

    if requested < 1:
        raise SystemExit("The CVE count must be at least 1.")

    return requested


if __name__ == "__main__":
    run_experiment(read_requested_count())