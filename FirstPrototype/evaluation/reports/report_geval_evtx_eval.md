# EVTX Report G-Eval Evaluation Report

Generated at: 2026-06-02T04:13:22.157734+00:00

## Executive Summary

This report evaluates whether FirstPrototype produces evidence-grounded final DFIR reports for selected EVTX Attack Samples. The subject LLM is local Ollama `sec-foundation:8b-gpu`; DeepEval G-Eval uses the OpenAI-compatible judge configured in `evaluation/.env`.

- Selected EVTX cases in preflight: `8`.
- Total cases: `1`.
- Run coverage: `subset/smoke`.
- Repetitions per case: `1`.
- Total output evaluations: `2`.
- Mean G-Eval score: `0.500`.
- Pass rate: `0.0%`.

## Methodology

This benchmark evaluates the final FirstPrototype DFIR report generated from EVTX Attack Samples. The subject under test is the full EVTX-to-report path: EVTX parsing, DeepLog anomaly detection, local Ollama LLM filtering, DFIR agent investigation, live threat-intel enrichment, and report rendering.

The candidate selection rule is deterministic: for each selected MITRE tactic folder, choose the largest `.evtx` file by byte size; if multiple files tie, choose the alphabetically earliest relative path. The v1 strata include only the eight named tactic folders and exclude `AutomatedTestingTools`, `Other`, metadata folders, and the root-level `UACME_59_Sysmon.evtx` file.

DeepEval `GEval` scores both structured JSON output and rendered Markdown output. The judge receives EVTX runtime context, expected tactic focus, anomaly summary, IOC/tool-result summary, and the final report. The scoring instructions explicitly penalize unsupported compromise claims, malicious labeling of private/internal IOCs without tool evidence, and severity inflation based only on anomaly volume.

The benchmark repeats each case to estimate stability. Stability is represented by pass rate, score standard deviation, and unique output hashes per output mode.

- Runner path: `D:\FAKI\FirstPrototype\evaluation\report_geval_evtx_runner.py`.
- DeepEval test entrypoint: `D:\FAKI\FirstPrototype\evaluation\tests\test_report_geval_evtx.py`.
- Dataset path: `D:\FAKI\FirstPrototype\evaluation\datasets\report_geval_evtx_cases.json`.
- Results path: `D:\FAKI\FirstPrototype\evaluation\results\report_geval_evtx_latest.json`.
- Runtime artifact directory: `D:\FAKI\FirstPrototype\evaluation\runtime\report_geval_evtx`.
- Selection rule: `largest EVTX by byte size per selected MITRE tactic folder; alphabetical relative path tie-breaker`.

## Selected EVTX Cases

| Case ID | Tactic | Selected EVTX | Size | Profile | Parsed Events | Windows | Anomalies | Detected | Cap Hit |
|---|---|---|---:|---|---:|---:|---:|---|---|
| evtx_command_and_control_largest | Command and Control | `Command and Control\bits_openvpn.evtx` | 1118208 | windows_apt | 1537 | 1537 | 1 | 1 | no |
| evtx_credential_access_largest | Credential Access | `Credential Access\CA_PetiPotam_etw_rpc_efsr_5_6.evtx` | 10555392 | windows_apt | 20000 | 20000 | 1 | 1 | yes |
| evtx_defense_evasion_largest | Defense Evasion | `Defense Evasion\DE_1102_security_log_cleared.evtx` | 1118208 | windows_apt | 112 | 112 | 14 | 1 | no |
| evtx_discovery_largest | Discovery | `Discovery\dicovery_4661_net_group_domain_admins_target.evtx` | 1118208 | windows_apt | 63 | 63 | 18 | 1 | no |
| evtx_execution_largest | Execution | `Execution\rogue_msi_url_1040_1042.evtx` | 1118208 | windows_apt | 351 | 351 | 347 | 1 | no |
| evtx_lateral_movement_largest | Lateral Movement | `Lateral Movement\LM_5145_Remote_FileCopy.evtx` | 1118208 | windows_apt | 869 | 869 | 855 | 1 | no |
| evtx_persistence_largest | Persistence | `Persistence\DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.evtx` | 1118208 | windows_apt | 28 | 28 | 2 | 1 | no |
| evtx_privilege_escalation_largest | Privilege Escalation | `Privilege Escalation\privesc_unquoted_svc_sysmon_1_11.evtx` | 1118208 | sysmon | 87 | 77 | 77 | 1 | no |

## Model and Runtime Configuration

- Subject under test: `FirstPrototype full EVTX report pipeline`.
- Subject LLM: `ollama::sec-foundation:8b-gpu` at `http://localhost:11434`.
- Judge model: `openai/gpt-5.4` through `https://api.koboillm.com/v1`.
- Threshold: `0.8`.
- Repetitions per case: `1`.
- Parsing cap: `20000` lines/events (`EVAL_REPORT_GEEVAL_MAX_LINES`).
- Output modes scored: `json, markdown`.
- Live threat-intel required keys ready: `True`.
- Core live keys present: `ABUSECH_API_KEY, ALIENVAULT_OTX_API_KEY, VIRUSTOTAL_API_KEY`.
- Optional live keys present: `none`.

## Live Enrichment Evidence

The subject pipeline performs IOC extraction and live threat-intel enrichment before report generation. G-Eval is instructed to treat missing, empty, private, or error-prone enrichment as evidence boundaries rather than as proof of benign or malicious behavior.

- Total extracted IOCs across runs: `152`.
- Internal/private IOC observations across runs: `0`.
- Tool calls across runs: `462`.
- Tool results across runs: `462`.
- Supporting evidence records across runs: `348`.
- Tool result status counts: `error=114, hash_not_found=4, illegal_search_term=40, no_exact_match=1, no_result=111, no_results=72, ok=120`.

## Aggregate G-Eval Results

| Metric | Value |
|---|---:|
| Total cases | 1 |
| Total case runs | 1 |
| Total output evaluations | 2 |
| Mean G-Eval score | 0.500 |
| Pass rate | 0.0% |

### JSON vs Markdown

| Output Mode | Runs | Mean Score | Pass Rate |
|---|---:|---:|---:|
| json | 1 | 0.400 | 0.0% |
| markdown | 1 | 0.600 | 0.0% |

### Macro Average per Tactic

| Tactic | Runs | Mean Score | Pass Rate |
|---|---:|---:|---:|
| Command and Control | 2 | 0.500 | 0.0% |

## Per-Case Results and Stability

| Case ID | Tactic | Runs | JSON Mean | Markdown Mean | Pass Rate | Score StdDev | Unique JSON/MD | Runtime Seconds Mean |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| evtx_command_and_control_largest | Command and Control | 1 | 0.400 | 0.600 | 0.0% | 0.100 | 1/1 | 339.85 |

## Failure Analysis

| Case ID | Run | Mode | Score | Success | Reason / Error |
|---|---:|---|---:|---|---|
| evtx_command_and_control_largest | 1 | json | 0.400 | False | The report correctly frames the case under Command and Control, includes concrete EVTX evidence such as Microsoft-Windows-Bits-Client EventID values, users like MSEDGEWIN10\\IEUser, timestamps, windows, and tool results. However, it poorly aligns with runti... |
| evtx_command_and_control_largest | 1 | markdown | 0.600 | False | The report aligns with the Command and Control tactic and cites concrete EVTX details such as Microsoft-Windows-Bits-Client EventID 61/3/59, users like MSEDGEWIN10\IEUser, destination IPs, windows, timestamps, and tool results. It stays mostly evidence-boun... |

## Limitations

- EVTX Attack Samples are attack-positive samples, but that does not mean every parsed event is malicious or that the generated report may claim compromise without evidence.
- Largest-file selection improves deterministic coverage of high-volume telemetry, but it can bias the dataset toward noisy samples rather than clinically representative incidents.
- The parser cap is `20000`. Large samples, especially the Credential Access PetiPotam EVTX, can hit the cap and must disclose that limitation.
- Live threat-intel APIs are variable over time. Empty, rate-limited, or error responses are part of the evidence boundary and should be reported as limitations.
- Private IPs, `.corp`, `.local`, `.example`, and similar internal identifiers are local telemetry by default; public enrichment absence should not be treated as proof of benign or malicious behavior.
- G-Eval is an LLM-as-judge metric. Repeated runs measure subject-output stability, but judge interpretation can still vary across model versions or provider behavior.
- The evaluation focuses on report quality and evidence alignment, not on proving that the underlying DeepLog anomaly detector is an authoritative attack classifier.
