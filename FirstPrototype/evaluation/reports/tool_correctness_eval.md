# Tool Use Correctness Evaluation Report

Generated at: 2026-07-01T03:40:02.101621+00:00

## Executive Summary

This evaluation measures whether FirstPrototype selects appropriate threat-intelligence tools for extracted IOCs. The subject under test is the local Ollama-backed `DFIRAgent.select_tools()` path, while DeepEval evaluates tool-call correctness using an OpenAI-compatible judge configured in `evaluation/.env`.

- Eval runner: `FirstPrototype DFIRAgent.select_tools`
- Test entrypoint: `D:\FAKI\FirstPrototype\evaluation\tests\test_tool_correctness.py`
- Dataset: `D:\FAKI\FirstPrototype\evaluation\datasets\tool_correctness_cases.json`
- Subject LLM: `ollama::sec-foundation:8b-gpu` at `http://localhost:11434`
- Judge model: `openai/gpt-5.4` at `https://api.koboillm.com/v1`
- Total cases: 6
- Repetitions per case: 3
- Mean ToolCorrectness score: 0.983
- Macro average by case: 0.983
- Pass rate at threshold 0.8: 100.0%
- Complete expected-tool coverage rate: 100.0%

## Methodology

Each dataset case supplies a DFIR context, extracted IOCs, and a golden set of expected tool calls. The runner invokes the FirstPrototype agent with a local Ollama client and converts selected `tool_calls` into DeepEval `ToolCall` objects. DeepEval `ToolCorrectnessMetric` compares selected tools against expected tools using input parameters (`ioc`, `ioc_type`) while ignoring ordering because the runtime can execute tools in parallel.

The benchmark repeats each case three times to estimate selection stability. The report distinguishes score failures from operational analysis fields: missing expected tools, extra selected tools, and argument mismatches.

## Metric Definition

- Primary metric: DeepEval `ToolCorrectnessMetric`.
- Evaluation params: `ToolCallParams.INPUT_PARAMETERS`.
- Required match fields: tool name, `ioc`, and `ioc_type`.
- Ordering: not considered.
- Exact match: disabled; extra tools are reported separately rather than automatically failing the DeepEval score.
- Threshold: `0.8`.

### Dataset Composition

- Cases: 6
- Total repeated runs: 18
- IOC type coverage: domain=2, ip=2, md5=1, sha256=1, url=2
- Academic categories: mixed_multi_ioc_coverage=1, single_domain_reputation=1, single_ip_reputation=1, single_md5_file_hash=1, single_sha256_file_hash=1, single_url_malware_delivery=1
- Expected tool coverage: abuseipdb_lookup=2, alienvault_otx_lookup=6, malwarebazaar_lookup=2, threatfox_lookup=8, urlhaus_lookup=2, virustotal_lookup=8

## Aggregate Results

| Category | Runs | Mean Score | Pass Rate |
|---|---:|---:|---:|
| mixed_multi_ioc_coverage | 3 | 0.900 | 100.0% |
| single_domain_reputation | 3 | 1.000 | 100.0% |
| single_ip_reputation | 3 | 1.000 | 100.0% |
| single_md5_file_hash | 3 | 1.000 | 100.0% |
| single_sha256_file_hash | 3 | 1.000 | 100.0% |
| single_url_malware_delivery | 3 | 1.000 | 100.0% |

## Per-Case Results

| Case ID | Category | Runs | Mean Score | Pass Rate | Stability | Missing Tools | Extra Tools |
|---|---:|---:|---:|---:|---:|---|---|
| tc_ip_reputation_001 | single_ip_reputation | 3 | 1.000 | 100.0% | 100.0% | None | None |
| tc_domain_reputation_001 | single_domain_reputation | 3 | 1.000 | 100.0% | 100.0% | None | None |
| tc_url_malware_delivery_001 | single_url_malware_delivery | 3 | 1.000 | 100.0% | 100.0% | None | None |
| tc_md5_file_hash_001 | single_md5_file_hash | 3 | 1.000 | 100.0% | 100.0% | None | None |
| tc_sha256_file_hash_001 | single_sha256_file_hash | 3 | 1.000 | 100.0% | 100.0% | None | None |
| tc_mixed_multi_ioc_001 | mixed_multi_ioc_coverage | 3 | 0.900 | 100.0% | 100.0% | None | None |

## Failure and Drift Analysis

| Case ID | Run | Score | Missing Tools | Extra Tools | Argument Mismatches | Reason |
|---|---:|---:|---|---|---:|---|
| None | - | - | None | None | 0 | All runs met the configured threshold and expected input parameters. |

## Reproducibility Notes

- Run the benchmark with `deepeval test run tests\test_tool_correctness.py` from `evaluation/`.
- Regenerate this report with `python report_tool_correctness.py` from `evaluation/`.
- The subject LLM is local Ollama; judge credentials are loaded only from `evaluation/.env`.
- The result JSON used for this report is `evaluation/results/tool_correctness_latest.json`.

## Limitations

- The benchmark evaluates tool selection, not the live correctness of external threat-intelligence API responses.
- Golden labels are expert-authored for representative IOC categories, not a statistically sampled incident corpus.
- The LLM judge can introduce evaluator variance; repeated case runs measure subject stability, not judge calibration.
- Extra tools are reported as potential over-selection but do not automatically reduce the DeepEval non-exact score.
