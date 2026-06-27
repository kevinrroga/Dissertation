"""
Day 5 — Confirm Claude (Sonnet 4.6) API access works.

Reads ANTHROPIC_API_KEY from the same .env file as the other provider keys.

Model choice: Sonnet 4.6 was selected over the Opus 4.7/4.8 tier because Opus
deprecated user-settable sampling parameters (temperature, top_p, top_k) at
the API level — sending temperature returns a 400 invalid_request_error.
Sonnet 4.6 still exposes temperature in the 0.0–1.0 range, which is required
to maintain an identical decoding configuration across all three providers
in this experiment. See decisions_2026-06-27_model-choice-and-decoding-config.md.

Note on reasoning: Claude's extended thinking is OFF by default. Unlike
GPT-5.5 (reasoning.effort) or DeepSeek V4 (thinking.type), there is no
separate "disable reasoning" flag to set here — simply not passing a
`thinking` parameter at all means standard (non-extended-thinking) mode,
which is the correct floor for matching the project's "reasoning off"
condition across providers.

Usage:
    pip install anthropic python-dotenv
    python test_claude.py
"""

import importlib
import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv

MODEL = "claude-sonnet-4-6"  # selected over Opus 4.7/4.8 because the Opus
# tier deprecated user-settable sampling parameters (temperature/top_p/top_k)
# at the API level (verified by direct 400 response on 2026-06-27); Sonnet 4.6
# still exposes temperature, which is required to maintain an identical
# decoding configuration across all three providers in this experiment.
OUTPUT_PATH = "claude_sample_response.json"


def test_claude_connection():
    load_dotenv()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY not found. Check your .env file contains "
            "a line like: ANTHROPIC_API_KEY=sk-ant..."
        )

    anthropic = importlib.import_module("anthropic")
    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        temperature=0,  # greedy decoding for deterministic extraction (Decision: decoding config)
        messages=[
            {"role": "user", "content": "Reply with exactly: API connection successful."}
        ],
        # No `thinking` parameter passed -> extended thinking stays off,
        # which is the genuine reasoning-off floor for this provider.
        # NOTE: do not also set top_p alongside temperature on 4.x-gen models —
        # use temperature alone.
    )

    output_text = response.content[0].text

    print("Raw output text:")
    print(output_text)

    # Log the model string the API actually used to serve this response.
    actual_model = getattr(response, "model", None)
    print(f"Model echoed back by API: {actual_model}")

    usage_dict = response.usage.model_dump() if response.usage else None

    sample_record = {
        "provider": "claude",
        "model_requested": MODEL,
        "model_echoed": actual_model,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "output_text": output_text,
        "usage": usage_dict,
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(sample_record, f, indent=2, default=str)

    print(f"\nSaved sample response to {OUTPUT_PATH}")
    print(f"Token usage: {usage_dict}")


if __name__ == "__main__":
    test_claude_connection()