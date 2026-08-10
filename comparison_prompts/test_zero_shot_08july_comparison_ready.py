"""
Final zero-shot experiment script.

What it does:
- Loads CVEs from the locked dataset.
- Sends the hybrid prompt to three models for a 10-CVE pilot.
- Validates the six-field JSON response.
- Prints live progress in the terminal.
- Saves after every CVE so the run can resume safely.
- Writes results to: data/results/zero-shot-hybrid-v3-test-10cves.json

Install:
    pip install openai anthropic python-dotenv

Run the default 10-CVE pilot:
    python zero_shot_hybrid_v3_10cves.py

Override the number of CVEs:
    python zero_shot_hybrid_v3_10cves.py 5
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
DATASET_PATH = ROOT / "data" / "datasets" / "dataset_v1_locked_24jun.json"
OUTPUT_PATH = ROOT / "comparison_prompts" / "results_cia_balanced_prompt_50.jsonl"
DEFAULT_CVE_COUNT = 50
TEMPERATURE = 0
PROMPT_CONDITION = "cia_balanced_prompt"

MODEL_NAMES = [
    "gpt-5.5",
    "claude-sonnet-4.6",
    "deepseek-v4-pro",
]

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


# Hybrid zero-shot prompt: targeted vulnerability-type changes,
# original attack-vector logic, and consequence-based CIA inference
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

- Return one short, standard vulnerability category describing the primary
  underlying technical weakness.
- Prefer the explicitly stated vulnerability type when one is given.
- If no standard type is explicitly stated, infer the most defensible
  vulnerability category from the described weakness and exploitation
  behaviour.
- Prefer the underlying weakness over the exploitation result or consequence.

Examples:
- Return "Command Injection" or "OS Command Injection", not
  "Remote Code Execution", when unsafe command construction is described.
- Return "Buffer Overflow", not "Denial of Service", when memory corruption
  is the identified weakness.
- Return "Server-Side Request Forgery", not "Information Disclosure", when
  attacker-controlled requests to internal or restricted resources are
  described.

- Prefer a more specific category only when the description clearly supports
  that specificity.
- Use "OS Command Injection" only when operating-system commands, shell
  commands, or command-line execution are clearly described.
- Use "Stack-Based Buffer Overflow" only when the stack is explicitly
  identified.
- Use a Cross-Site Scripting subtype only when the subtype is explicitly
  stated or clearly demonstrated.

- Distinguish authentication from authorization:
  - Authentication concerns verifying identity, credentials, tokens,
    certificates, passwords, or login state.
  - Authorization concerns whether an authenticated identity is permitted to
    access a resource or perform an action.
  - The presence of an HTTP "Authorization" header does not by itself make the
    weakness an authorization flaw.

- If several weaknesses are described, return the primary weakness most
  directly associated with the reported vulnerability.
- Return one vulnerability type only.
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

Infer CIA impact from the practical consequences described or reasonably
implied by the vulnerability.

- "High": exploitation gives broad or complete compromise of the relevant
  security property.
- "Low": the effect is limited, partial, temporary, or restricted in scope.
- "None": the described vulnerability and attacker capability do not provide a
  practical means to affect that security property.
- null: the description does not provide enough information for a defensible
  determination.

Do not assign CIA values solely from the vulnerability type. However, reasonable
CVSS-style inference is allowed when the described attacker capability clearly
implies an impact.

Confidentiality:
- Unauthorized reading, disclosure, interception, credential exposure, or
  access to sensitive data supports confidentiality impact.
- High confidentiality impact may be inferred when exploitation provides broad
  access to sensitive system, user, or credential data.
- Low confidentiality impact may apply when disclosure is limited in scope,
  sensitivity, or volume.
- Do not infer confidentiality impact when the attacker capability only affects
  execution, modification, or disruption and provides no practical means to
  access protected information.

Integrity:
- Unauthorized modification, deletion, creation, command execution, code
  execution, configuration change, or control of system behaviour supports
  integrity impact.
- High integrity impact may be inferred when exploitation gives broad or
  privileged control over software, system state, configuration, or critical
  data.
- Low integrity impact may apply when modification is limited to a narrow,
  non-critical, or recoverable scope.
- Do not infer integrity impact when the capability is read-only and provides no
  practical means to alter data or system behaviour.

Availability:
- Crashes, service interruption, resource exhaustion, deletion, destructive
  actions, or loss of control over a critical service support availability
  impact.
- High availability impact may be inferred when exploitation provides broad or
  privileged control of the affected system, such as arbitrary code or
  operating-system command execution, because that capability can reasonably
  enable the attacker to stop services, damage system state, or make the system
  unusable.
- Low availability impact may apply when disruption is limited, temporary,
  recoverable, or restricted to a non-critical component.
- Do not infer availability impact merely because confidentiality or integrity
  is affected. The attacker capability must provide a practical means to
  disrupt or disable the system or service.

General rules:
- Broad system compromise may support High impact across multiple security
  properties.
- Do not automatically interpret an unmentioned impact as "None".
- An overall publisher severity label is not evidence for an individual CIA
  impact.

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



def resolve_comparison_ids_path() -> Path:
    """Find comparison_cve_ids.json in the expected project locations."""
    candidates = [
        Path(__file__).resolve().parent / "comparison_cve_ids.json",
        ROOT / "data" / "comparison" / "comparison_cve_ids.json",
        ROOT / "data" / "datasets" / "comparison_cve_ids.json",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    searched = "\n".join(str(path.resolve()) for path in candidates)
    raise SystemExit(
        "\ncomparison_cve_ids.json was not found. Checked:\n"
        f"{searched}"
    )


def load_dataset() -> list[dict]:
    """Load exactly the 50 CVEs listed in comparison_cve_ids.json."""
    if not DATASET_PATH.exists():
        raise SystemExit(
            f"\nDataset not found:\n{DATASET_PATH.resolve()}\n"
            "Check DATASET_PATH near the top of this script."
        )

    comparison_ids_path = resolve_comparison_ids_path()

    with DATASET_PATH.open("r", encoding="utf-8") as file:
        records = json.load(file)

    with comparison_ids_path.open("r", encoding="utf-8") as file:
        comparison_ids = json.load(file)

    if not isinstance(records, list) or not records:
        raise SystemExit("The dataset must be a non-empty JSON list.")

    if not isinstance(comparison_ids, list):
        raise SystemExit(
            "comparison_cve_ids.json must contain a JSON list of CVE IDs."
        )

    if len(comparison_ids) != 50:
        raise SystemExit(
            f"Expected exactly 50 comparison CVE IDs, found {len(comparison_ids)}."
        )

    if len(set(comparison_ids)) != len(comparison_ids):
        raise SystemExit("comparison_cve_ids.json contains duplicate CVE IDs.")

    records_by_id = {
        record.get("cve_id"): record
        for record in records
        if record.get("cve_id")
    }

    missing_ids = [
        cve_id
        for cve_id in comparison_ids
        if cve_id not in records_by_id
    ]

    if missing_ids:
        raise SystemExit(
            "The following comparison CVEs were not found in the locked dataset:\n"
            + "\n".join(missing_ids)
        )

    selected = [records_by_id[cve_id] for cve_id in comparison_ids]

    print(f"Loaded {len(selected)} fixed comparison CVEs.")
    print(f"Comparison IDs: {comparison_ids_path.resolve()}")
    print(f"Locked dataset: {DATASET_PATH.resolve()}")

    return selected


def load_existing_results() -> list[dict]:
    """Load prior JSONL rows so completed model/CVE pairs can be skipped."""
    if not OUTPUT_PATH.exists():
        return []

    rows = []

    with OUTPUT_PATH.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise SystemExit(
                    f"Invalid JSONL at {OUTPUT_PATH.resolve()}, "
                    f"line {line_number}: {error}"
                )

            if not isinstance(row, dict):
                raise SystemExit(
                    f"Invalid JSONL object at line {line_number}: "
                    "each line must contain one JSON object."
                )

            rows.append(row)

    print(
        f"Resuming from {OUTPUT_PATH.resolve()} "
        f"with {len(rows)} existing rows."
    )
    return rows


def append_result(row: dict) -> None:
    """Append one complete result row to the JSONL output."""
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("a", encoding="utf-8") as file:
        file.write(json.dumps(row, ensure_ascii=False) + "\n")
        file.flush()


def completed_cve_ids(results: list[dict], model_name: str) -> set[str]:
    """Return CVEs already successfully processed for one model."""
    return {
        row.get("cve_id")
        for row in results
        if row.get("model") == model_name and row.get("valid") is True
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


def call_gpt(prompt: str) -> tuple[str, dict, str | None]:
    """Call GPT-5.5 with reasoning disabled."""
    from openai import OpenAI

    client = OpenAI(api_key=require_api_key("OPENAI_API_KEY"))
    response = client.responses.create(
        model="gpt-5.5",
        input=prompt,
        reasoning={"effort": "none"},
        temperature=TEMPERATURE,
    )

    usage = getattr(response, "usage", None)
    usage_data = {
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }
    return response.output_text, usage_data, getattr(response, "model", None)


def call_claude(prompt: str) -> tuple[str, dict, str | None]:
    """Call Claude Sonnet 4.6."""
    import anthropic

    client = anthropic.Anthropic(api_key=require_api_key("ANTHROPIC_API_KEY"))
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        temperature=TEMPERATURE,
        messages=[{"role": "user", "content": prompt}],
    )

    usage = getattr(response, "usage", None)
    input_tokens = getattr(usage, "input_tokens", None)
    output_tokens = getattr(usage, "output_tokens", None)
    usage_data = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": (
            input_tokens + output_tokens
            if input_tokens is not None and output_tokens is not None
            else None
        ),
    }
    return response.content[0].text, usage_data, getattr(response, "model", None)


def call_deepseek(prompt: str) -> tuple[str, dict, str | None]:
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

    usage = getattr(response, "usage", None)
    usage_data = {
        "input_tokens": getattr(usage, "prompt_tokens", None),
        "output_tokens": getattr(usage, "completion_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
    }
    return (
        response.choices[0].message.content,
        usage_data,
        getattr(response, "model", None),
    )


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


def run_experiment() -> None:
    cves = load_dataset()
    results = load_existing_results()

    total_models = len(MODEL_NAMES)
    total_cves = len(cves)

    for model_number, model_name in enumerate(MODEL_NAMES, start=1):
        print("\n" + "=" * 72)
        print(f"MODEL {model_number}/{total_models}: {model_name}")
        print("=" * 72)

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
                row = {
                    "cve_id": cve_id,
                    "prompt_condition": PROMPT_CONDITION,
                    "model": model_name,
                    "description": description,
                    "valid": False,
                    "parsed": None,
                    "error": "Missing description",
                }
                append_result(row)
                results.append(row)
                continue

            prompt = ZERO_SHOT_TEMPLATE.format(description=description)
            started = time.perf_counter()

            try:
                raw, usage, served_model = call_with_retry(
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
                    "prompt_condition": PROMPT_CONDITION,
                    "model": model_name,
                    "description": description,
                    "raw_response": raw,
                    "valid": valid,
                    "parsed": parsed,
                    "notes": notes,
                    "latency_s": round(elapsed, 3),
                    "usage": usage,
                    "served_model": served_model,
                }

            except Exception as error:
                elapsed = time.perf_counter() - started
                print(f"  FAILED after {elapsed:.2f}s: {error}")
                row = {
                    "cve_id": cve_id,
                    "prompt_condition": PROMPT_CONDITION,
                    "model": model_name,
                    "description": description,
                    "valid": False,
                    "error": str(error),
                    "latency_s": round(elapsed, 3),
                }

            append_result(row)
            results.append(row)

        valid_count = sum(
            1
            for row in results
            if row.get("model") == model_name and row.get("valid") is True
        )
        print(
            f"\nCompleted {model_name}: "
            f"{valid_count}/{total_cves} valid responses."
        )

    print("\n" + "=" * 72)
    print("EXPERIMENT FINISHED")
    print(f"Results saved to:\n{OUTPUT_PATH.resolve()}")
    print("=" * 72)


if __name__ == "__main__":
    run_experiment()
