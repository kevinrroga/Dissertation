"""
Day 5 — Confirm DeepSeek (V4) API access works.

DeepSeek's API is OpenAI-compatible, so we reuse the openai SDK
with a different base_url. Reads DEEPSEEK_API_KEY from the same
.env file as your NVD and OpenAI keys.

Usage:
    pip install python-dotenv openai
    python test_deepseek.py
"""

import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from openai import OpenAI

MODEL = "deepseek-v4-pro"  # use "deepseek-v4-pro" for the larger tier
BASE_URL = "https://api.deepseek.com"
OUTPUT_PATH = "deepseek_sample_response.json"


def test_deepseek_connection():
    load_dotenv()

    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError(
            "DEEPSEEK_API_KEY not found. Check your .env file contains "
            "a line like: DEEPSEEK_API_KEY=sk-..."
        )

    client = OpenAI(api_key=api_key, base_url=BASE_URL)

    # IMPORTANT: DeepSeek V4 defaults to thinking mode ENABLED, not disabled.
    # Confirmed by a live test call returning reasoning_tokens > 0 with no
    # extra_body set. Must explicitly pass thinking: disabled to match
    # Decision 4 (reasoning off across all three models).
    # temperature=0 is honoured ONLY because thinking is disabled here; in
    # thinking mode DeepSeek silently ignores temperature.
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "user", "content": "Reply with exactly: API connection successful."}
        ],
        temperature=0,  # greedy decoding for deterministic extraction
        extra_body={"thinking": {"type": "disabled"}},
    )

    output_text = response.choices[0].message.content

    print("Raw output text:")
    print(output_text)

    sample_record = {
        "provider": "deepseek",
        "model": MODEL,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "output_text": output_text,
        "usage": response.usage.model_dump() if response.usage else None,
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(sample_record, f, indent=2)

    print(f"\nSaved sample response to {OUTPUT_PATH}")
    print(f"Token usage: {sample_record['usage']}")


if __name__ == "__main__":
    test_deepseek_connection()