# Report Generation G-Eval Resume

Generated at: 2026-06-05T02:51:20.646646+00:00

## High-Level Result

- Source JSON: `D:\FAKI\FirstPrototype\evaluation\results\report_generation_geval_latest.json`.
- Source size: `429566` bytes.
- Evidence mode: `frozen_replay`.
- Subject model: `sec-foundation:8b-gpu`.
- Judge model: `openai/gpt-5.4`.
- Prompt strategy: `evidence_brief_tactic_guided_v1`.
- G-Eval metric mode: `dimensional_v1`.
- Metric preset: `full`.
- Metric dimensions: `['Evidence Groundedness', 'Severity Calibration', 'Tactic Alignment', 'Recommendation Specificity', 'Limitation Honesty']`.
- Judge cache enabled: `False`.
- Skip judge if deterministic fails: `True`.
- Total cases: `8`.
- Case runs: `16`.
- Output evaluations: `16`.
- Quality output evaluations: `16`.
- Judge-error output evaluations: `0`.
- Judge-skipped output evaluations: `0`.
- Judge-cache hits: `0`.
- Deterministic precheck failures: `0`.
- Mean G-Eval score: `0.863`.
- Mean quality G-Eval score: `0.863`.
- Pass rate: `100.0%`.
- Quality pass rate: `100.0%`.

## Evidence Totals

- IOCs: `152`.
- Internal/private IOCs: `15`.
- Tool results: `470`.
- Tool statuses: `{'error': 157, 'hash_not_found': 77, 'illegal_search_term': 3, 'no_result': 149, 'no_results': 3, 'ok': 81}`.

## JSON vs Markdown

| Mode | Runs | Mean Score | Pass Rate |
|---|---:|---:|---:|
| summary | 16 | 0.863 | 100.0% |

## Metric Dimensions

| Dimension | Runs | Mean Score | Pass Rate | Min | Max |
|---|---:|---:|---:|---:|---:|
| Evidence Groundedness | 16 | 0.825 | 87.5% | 0.700 | 0.900 |
| Limitation Honesty | 16 | 0.875 | 100.0% | 0.800 | 0.900 |
| Recommendation Specificity | 16 | 0.838 | 87.5% | 0.700 | 0.900 |
| Severity Calibration | 16 | 0.875 | 100.0% | 0.800 | 0.900 |
| Tactic Alignment | 16 | 0.900 | 100.0% | 0.800 | 1.000 |

## Tactic Ranking

| Tactic | Runs | Mean Score | Pass Rate |
|---|---:|---:|---:|
| Credential Access | 2 | 0.820 | 100.0% |
| Lateral Movement | 2 | 0.820 | 100.0% |
| Privilege Escalation | 2 | 0.840 | 100.0% |
| Command and Control | 2 | 0.860 | 100.0% |
| Discovery | 2 | 0.860 | 100.0% |
| Persistence | 2 | 0.860 | 100.0% |
| Defense Evasion | 2 | 0.920 | 100.0% |
| Execution | 2 | 0.920 | 100.0% |

## Per-Case Resume

| Case ID | Tactic | Anomalies | IOCs | Tools | JSON Mean | Markdown Mean | Pass Rate |
|---|---|---:|---:|---:|---:|---:|---:|
| evtx_command_and_control_largest | Command and Control | 1 | 7 | 21 | 0.000 | 0.000 | 100.0% |
| evtx_credential_access_largest | Credential Access | 1 | 0 | 0 | 0.000 | 0.000 | 100.0% |
| evtx_defense_evasion_largest | Defense Evasion | 14 | 3 | 11 | 0.000 | 0.000 | 100.0% |
| evtx_discovery_largest | Discovery | 18 | 11 | 43 | 0.000 | 0.000 | 100.0% |
| evtx_execution_largest | Execution | 347 | 0 | 0 | 0.000 | 0.000 | 100.0% |
| evtx_lateral_movement_largest | Lateral Movement | 855 | 48 | 145 | 0.000 | 0.000 | 100.0% |
| evtx_persistence_largest | Persistence | 2 | 3 | 10 | 0.000 | 0.000 | 100.0% |
| evtx_privilege_escalation_largest | Privilege Escalation | 77 | 80 | 240 | 0.000 | 0.000 | 100.0% |

## Main Failure Clusters

- `Credential Access`: mean `0.820`, pass `100.0%`.
- `Lateral Movement`: mean `0.820`, pass `100.0%`.
- `Privilege Escalation`: mean `0.840`, pass `100.0%`.

## Failure Count

- Failed output evaluations: `0`.
- Full reasons are in the compact JSON under `failures`; the original verbose output remains in the source JSON.
