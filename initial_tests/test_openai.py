"""
Day 5 — Confirm OpenAI (GPT-5.5) API access works.

Reads OPENAI_API_KEY from a .env file in the same project
(the same file your NVD_API_KEY already lives in).

"""

import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from openai import OpenAI

MODEL = "gpt-5.5"
OUTPUT_PATH = "openai_sample_response.json"


def test_openai_connection():
    load_dotenv()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY not found. Check that your .env file exists "
            "in this directory (or pass its path to load_dotenv()) and "
            "contains a line like: OPENAI_API_KEY=sk-..."
        )

    client = OpenAI(api_key=api_key)

    # Reasoning off to match the main experiment configuration.
    response = client.responses.create(
        model=MODEL,
        input="Reply with exactly: API connection successful.",
        reasoning={"effort": "none"},
    )

    output_text = response.output_text

    print("Raw output text:")
    print(output_text)

    sample_record = {
        "provider": "openai",
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
    test_openai_connection()