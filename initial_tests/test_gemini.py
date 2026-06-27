"""
Day 5 — Confirm Gemini (3.1 Pro) API access works.

Reads GEMINI_API_KEY from the same .env file as your NVD, OpenAI,
and DeepSeek keys.

Note: Gemini 3.1 Pro CANNOT fully disable thinking (unlike GPT-5.5
and DeepSeek V4). "minimal" is only available on Flash/Flash-Lite.
For Pro, "low" is the lowest available setting — this is an
asymmetry across providers, document it in the Decision Log.

Usage:
    pip install google-genai python-dotenv
    python test_gemini.py
"""

import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from google import genai
from google.genai import types

MODEL = "gemini-3.5-flash"
OUTPUT_PATH = "gemini_sample_response.json"


def test_gemini_connection():
    load_dotenv()

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY not found. Check your .env file contains "
            "a line like: GEMINI_API_KEY=your-key-here"
        )

    client = genai.Client(api_key=api_key)

    # "low" is the lowest thinking level available on 3.1 Pro
    # (minimal/off does not exist for this model — see note above).
    response = client.models.generate_content(
        model=MODEL,
        contents="Reply with exactly: API connection successful.",
        config=types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_level="low")
        ),
    )

    output_text = response.text

    print("Raw output text:")
    print(output_text)

    usage = response.usage_metadata
    usage_dict = usage.model_dump() if usage else None

    sample_record = {
        "provider": "gemini",
        "model": MODEL,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "output_text": output_text,
        "usage": usage_dict,
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(sample_record, f, indent=2, default=str)

    print(f"\nSaved sample response to {OUTPUT_PATH}")
    print(f"Token usage: {usage_dict}")


if __name__ == "__main__":
    test_gemini_connection()