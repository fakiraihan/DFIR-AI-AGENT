# Report Generation G-Eval Replay Report

Generated at: 2026-06-05T02:51:15.728336+00:00

## Executive Summary

This evaluation isolates FirstPrototype report generation by replaying frozen EVTX evidence. Parsing, DeepLog detection, and live threat-intel enrichment are not repeated during G-Eval runs; only the local Ollama report-generation LLM and deterministic report rendering are exercised.

- Evidence mode: `frozen_replay`.
- Capture mode: `one_full_pipeline_run_per_case`.
- Fixture generated at: `2026-06-02T05:14:05.297695+00:00`.
- Total cases: `8`.
- Repetitions per case: `2`.
- Mean G-Eval score: `0.863`.
- Pass rate: `100.0%`.

## Methodology

Phase 1 captures one runtime-like full-pipeline evidence state per EVTX case. The capture uses the runtime-like validation profile, executes threat-intel tools, and stores anomaly, IOC, tool-result, correlation, timeline, and supporting-evidence fields as a fixture.

Phase 2 repeats report generation from the frozen fixture. Each replay clears prior `investigation_summary` and `recommendations`, injects an evidence brief into the report-generation prompt, invokes local Ollama `sec-foundation:8b-gpu` through `DFIRAgent.generate_summary()`, optionally evaluates the raw LLM `summary` output, renders JSON/Markdown through `ReportGenerator`, and scores outputs with dimensional DeepEval G-Eval using `openai/gpt-5.4` from `evaluation/.env`.

- Runner path: `D:\FAKI\FirstPrototype\evaluation\report_generation_geval_runner.py`.
- Test entrypoint: `D:\FAKI\FirstPrototype\evaluation\tests\test_report_generation_geval.py`.
- Fixture path: `D:\FAKI\FirstPrototype\evaluation\datasets\report_generation_evidence_cases.json`.
- Results path: `D:\FAKI\FirstPrototype\evaluation\results\report_generation_geval_latest.json`.
- Runtime dir: `D:\FAKI\FirstPrototype\evaluation\runtime\report_generation_geval`.
- Subject LLM: `ollama::sec-foundation:8b-gpu` at `http://localhost:11434`.
- Judge: `openai/gpt-5.4` at `https://api.koboillm.com/v1`.
- Prompt strategy: `evidence_brief_tactic_guided_v1`.
- G-Eval metric mode: `dimensional_v1`.
- Metric preset: `full`.
- Metric dimensions: `['Evidence Groundedness', 'Severity Calibration', 'Tactic Alignment', 'Recommendation Specificity', 'Limitation Honesty']`.
- Judge cache enabled: `False`.
- Skip judge if deterministic fails: `True`.
- Live threat-intel per replay: `False`.

## Frozen Evidence Cases

| Case ID | Tactic | EVTX | Profile | Parsed | Anomalies | IOCs | Tool Results | Capture Seconds | Cap Hit |
|---|---|---|---|---:|---:|---:|---:|---:|---|
| evtx_command_and_control_largest | Command and Control | `Command and Control\bits_openvpn.evtx` | windows_apt | 1537 | 1 | 7 | 21 | 357.42 | no |
| evtx_credential_access_largest | Credential Access | `Credential Access\CA_PetiPotam_etw_rpc_efsr_5_6.evtx` | windows_apt | 20000 | 1 | 0 | 0 | 584.93 | yes |
| evtx_defense_evasion_largest | Defense Evasion | `Defense Evasion\DE_1102_security_log_cleared.evtx` | windows_apt | 112 | 14 | 3 | 11 | 44.86 | no |
| evtx_discovery_largest | Discovery | `Discovery\dicovery_4661_net_group_domain_admins_target.evtx` | windows_apt | 63 | 18 | 11 | 43 | 28.57 | no |
| evtx_execution_largest | Execution | `Execution\rogue_msi_url_1040_1042.evtx` | windows_apt | 351 | 347 | 0 | 0 | 7.57 | no |
| evtx_lateral_movement_largest | Lateral Movement | `Lateral Movement\LM_5145_Remote_FileCopy.evtx` | windows_apt | 869 | 855 | 48 | 145 | 74.87 | no |
| evtx_persistence_largest | Persistence | `Persistence\DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx` | windows_apt | 28 | 2 | 3 | 10 | 15.60 | no |
| evtx_privilege_escalation_largest | Privilege Escalation | `Privilege Escalation\privesc_unquoted_svc_sysmon_1_11.evtx` | sysmon | 87 | 77 | 80 | 240 | 65.19 | no |

## Frozen Tool Evidence

Tool evidence is captured once during evidence capture and replayed unchanged during G-Eval. No live threat-intel API calls are made during replay runs.

- Frozen IOC count across selected cases: `152`.
- Frozen internal/private IOC count: `15`.
- Frozen tool-result count: `470`.
- Frozen tool-result status counts: `error=157, hash_not_found=77, illegal_search_term=3, no_result=149, no_results=3, ok=81`.

## Aggregate Replay Results

| Metric | Value |
|---|---:|
| Total cases | 8 |
| Total case runs | 16 |
| Total output evaluations | 16 |
| Quality output evaluations | 16 |
| Judge-error output evaluations | 0 |
| Judge-skipped output evaluations | 0 |
| Judge-cache hits | 0 |
| Deterministic precheck failures | 0 |
| Mean G-Eval score | 0.863 |
| Mean quality G-Eval score | 0.863 |
| Pass rate | 100.0% |
| Quality pass rate | 100.0% |

### JSON vs Markdown

| Output Mode | Runs | Mean Score | Pass Rate |
|---|---:|---:|---:|
| summary | 16 | 0.863 | 100.0% |

### Macro Average per Tactic

| Tactic | Runs | Mean Score | Pass Rate |
|---|---:|---:|---:|
| Command and Control | 2 | 0.860 | 100.0% |
| Credential Access | 2 | 0.820 | 100.0% |
| Defense Evasion | 2 | 0.920 | 100.0% |
| Discovery | 2 | 0.860 | 100.0% |
| Execution | 2 | 0.920 | 100.0% |
| Lateral Movement | 2 | 0.820 | 100.0% |
| Persistence | 2 | 0.860 | 100.0% |
| Privilege Escalation | 2 | 0.840 | 100.0% |

### G-Eval Metric Dimensions

| Dimension | Runs | Mean Score | Pass Rate |
|---|---:|---:|---:|
| Evidence Groundedness | 16 | 0.825 | 87.5% |
| Limitation Honesty | 16 | 0.875 | 100.0% |
| Recommendation Specificity | 16 | 0.838 | 87.5% |
| Severity Calibration | 16 | 0.875 | 100.0% |
| Tactic Alignment | 16 | 0.900 | 100.0% |

## Per-Case Replay Stability

| Case ID | Tactic | Runs | JSON Mean | Markdown Mean | Pass Rate | Score StdDev | Unique JSON/MD | Runtime Seconds Mean |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| evtx_command_and_control_largest | Command and Control | 2 | 0.000 | 0.000 | 100.0% | 0.000 | 0/0 | 2.78 |
| evtx_credential_access_largest | Credential Access | 2 | 0.000 | 0.000 | 100.0% | 0.000 | 0/0 | 0.02 |
| evtx_defense_evasion_largest | Defense Evasion | 2 | 0.000 | 0.000 | 100.0% | 0.000 | 0/0 | 3.72 |
| evtx_discovery_largest | Discovery | 2 | 0.000 | 0.000 | 100.0% | 0.000 | 0/0 | 3.05 |
| evtx_execution_largest | Execution | 2 | 0.000 | 0.000 | 100.0% | 0.000 | 0/0 | 0.51 |
| evtx_lateral_movement_largest | Lateral Movement | 2 | 0.000 | 0.000 | 100.0% | 0.000 | 0/0 | 4.87 |
| evtx_persistence_largest | Persistence | 2 | 0.000 | 0.000 | 100.0% | 0.000 | 0/0 | 2.24 |
| evtx_privilege_escalation_largest | Privilege Escalation | 2 | 0.000 | 0.000 | 100.0% | 0.000 | 0/0 | 2.90 |

## Failure Analysis

| Case ID | Run | Mode | Score | Success | Judge Error | Reason / Error |
|---|---:|---|---:|---|---|---|
| None | - | - | - | - | - | All evaluated outputs met the configured threshold. |

## Limitations

- This benchmark evaluates report generation under fixed evidence, not end-to-end detector quality.
- Frozen live-enrichment evidence is timestamped and may differ from future external API responses.
- Replayed report quality can expose prompt/report-generation issues but cannot prove the original anomaly detector is correct.
- Because evidence is fixed, stability reflects local LLM report-generation variance and judge variance rather than parsing or tool API variance.
- Judge endpoint failures such as budget exhaustion are counted separately as judge-error evaluations and should not be interpreted as report-quality failures.
- EVTX Attack Samples are attack-positive samples; generated reports must still avoid unsupported compromise claims.
