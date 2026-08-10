# cve-ner-dissertation

Dissertation project evaluating LLMs (GPT-5.5, Claude Sonnet 4.6, DeepSeek V4)
on structured entity extraction from CVE/NVD vulnerability descriptions —
comparing zero-shot vs few-shot prompting (RQ2) across a locked 500-CVE
dataset built from the NVD API 2.0.

## Directory map

| Folder | Contents |
|---|---|
| [`initial_tests/`](initial_tests/README.md) | Day 5 — one-off scripts confirming each model provider's API works. |
| [`scripts/fetching/`](scripts/fetching/README.md) | Day 1–2 — building blocks for pulling CVE data out of the NVD API. |
| [`scripts/dataset/`](scripts/dataset/README.md) | Day 3 — scaling the fetch loop into the final locked 500-CVE dataset. |
| [`scripts/experiments/`](scripts/experiments/README.md) | Day 6–14 — the zero-shot / few-shot prompt experiment runners. |
| [`scripts/validation/`](scripts/validation/README.md) | Day 8 — the JSON validation/retry layer and its test suite. |
| [`chatgpt_interference/`](chatgpt_interference/README.md) | Zero-shot pilot/final scripts produced with ChatGPT's help, kept separate from the main `scripts/experiments/` line of work. |
| [`data/`](data/README.md) | All inputs and outputs: NVD pipeline steps, the locked dataset, prompts, model samples, and experiment results. |
| [`reports/`](reports/README.md) | Human-readable summaries: metrics CSVs, run logs, and verification/inspection reports. |

## Setup

Copy your API keys into `.env` (see `initial_tests/` for which keys each
provider needs) and `pip install -r` the packages referenced in each
script's docstring (`openai`, `anthropic`, `google-genai`, `python-dotenv`,
`requests`).

## Day numbering

Scripts and files are named after the day of the dissertation timeline they
were produced on (Day 1, Day 3, Day 6, Day 7, Day 9, Day 11...). Each
folder's README explains what that day's deliverable was and how the files
inside relate to one another (final version vs. superseded draft).
