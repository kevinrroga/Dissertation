# initial_tests/

Day 5 deliverable: one throwaway script per model provider, each doing
nothing but confirming the API key works and a basic call returns a
response. Not part of the experiment pipeline — just connectivity checks
that were kept for reference.

- **test_claude.py** — Confirms Claude (Sonnet 4.6) API access. Notes why
  Sonnet 4.6 was picked over Opus 4.7+ (Opus rejects a user-set
  `temperature`, which breaks the identical-decoding-config requirement
  across providers). Reads `ANTHROPIC_API_KEY` from `.env`.
- **test_deepseek.py** — Confirms DeepSeek access using `deepseek-v4-flash`
  via the OpenAI-compatible SDK against DeepSeek's `base_url`. Reads
  `DEEPSEEK_API_KEY` from `.env`.
- **test_deepseek2.py** — Same as above but targets `deepseek-v4-pro` (the
  larger tier actually used in the experiments) instead of the flash model.
- **test_gemini.py** — Confirms Gemini (3.1 Pro) access. Notes that Gemini
  can't fully disable "thinking" the way GPT-5.5/DeepSeek can — documented
  as a cross-provider asymmetry. Gemini was later dropped from the project
  in favor of Claude (see `chatgpt_interference/` and `scripts/experiments/`
  docstrings for why).
- **test_openai.py** — Confirms OpenAI (GPT-5.5) API access using
  `OPENAI_API_KEY` from `.env`.

Each file prints/saves a sample response (see `data/model_samples/`) so the
raw shape of each provider's output could be inspected before building the
real extraction prompts.
