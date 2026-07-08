# Evaluation

This folder owns DeepEval configuration and eval artifacts..

## Environment

```env
OPENAI_API_KEY=your_koboillm_api_key
OPENAI_BASE_URL=https://api.koboillm.com/v1
OPENAI_MODEL_NAME=openai/gpt-5.4
```

DeepEval reads OpenAI-compatible judge settings from these variables. Use `OPENAI_MODEL_NAME` to switch models:

```env
OPENAI_MODEL_NAME=gemini/gemini-3-pro-preview
OPENAI_MODEL_NAME=vertex_ai/moonshotai/kimi-k2-thinking-maas
OPENAI_MODEL_NAME=vertex_ai/deepseek-ai/deepseek-v3.2-maas
```

## Running Evals

From this folder, load the env file and run DeepEval against eval tests:

```powershell
Get-Content .env | ForEach-Object {
  if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
    [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), 'Process')
  }
}

deepeval test run tests
```

## EVTX Report G-Eval

The EVTX report-quality benchmark uses the full FirstPrototype report pipeline
with local Ollama `sec-foundation:8b-gpu` as the subject LLM. DeepEval G-Eval
uses `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `OPENAI_MODEL_NAME` from this
folder's `.env`.

```powershell
deepeval test run tests\test_koboillm_connection.py
python report_geval_evtx_runner.py --preflight
deepeval test run tests\test_report_geval_evtx.py
python report_geval_evtx_reporter.py
```

Artifacts are written under `evaluation/results/`,
`evaluation/runtime/report_geval_evtx/`, and
`evaluation/reports/report_geval_evtx_eval.md`.

## Report Generation G-Eval Replay

Use this faster strategy when the evaluation focus is report generation quality,
not repeated EVTX parsing, DeepLog detection, or live API variance.

```powershell
python report_generation_geval_runner.py --capture-evidence
python report_generation_geval_runner.py --preflight
deepeval test run tests\test_report_generation_geval.py
python report_generation_geval_reporter.py
```

Capture mode performs one runtime-like full-pipeline run per selected EVTX case
and stores frozen evidence in
`evaluation/datasets/report_generation_evidence_cases.json`. Replay mode clears
prior summaries/recommendations, invokes local Ollama `sec-foundation:8b-gpu`,
renders JSON/Markdown reports, and judges them with G-Eval.
