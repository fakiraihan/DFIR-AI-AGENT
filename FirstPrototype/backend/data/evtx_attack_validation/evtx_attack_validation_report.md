# EVTX Attack Validation Report

Validation root: `D:\FAKI\LogADEmpirical-dev\EVTX-ATTACK-SAMPLES`

Generated files:

- `evtx_attack_validation.csv`
- `evtx_attack_validation_summary.json`
- `missed_topk10.csv`
- `missed_topk5.csv`

## What This Measures

Every EVTX sample in the attack corpus is treated as an attack-positive file.
The score is sample-level recall: whether DeepLog emits at least one anomaly
window for that file. This is a validation harness, not a rule-based detector.

## Global Top-K Sweep

| Top-K | Detected Files | Missed Files | Sample Recall | Anomaly Window Ratio |
| --- | ---: | ---: | ---: | ---: |
| 3 | 117 / 278 | 161 | 0.4209 | 0.0517 |
| 5 | 101 / 278 | 177 | 0.3633 | 0.0452 |
| 10 | 75 / 278 | 203 | 0.2698 | 0.0415 |
| 14 | 74 / 278 | 204 | 0.2662 | 0.0410 |

## Runtime-Like Scenarios

| Scenario | Detected Files | Missed Files | Sample Recall | Anomaly Window Ratio |
| --- | ---: | ---: | ---: | ---: |
| Previous runtime-like: Sysmon top-3 + Windows APT top-10 | 111 / 278 | 167 | 0.3993 | 0.0503 |
| Current recommended: Sysmon top-3 + Windows APT top-5 | 116 / 278 | 162 | 0.4173 | 0.0511 |
| Aggressive: all profiles top-3 | 117 / 278 | 161 | 0.4209 | 0.0517 |

## Recommended Runtime Setting

Use `WINDOWS_APT_DEEPLOG_TOPK=5`.

It recovers five additional Windows Security/EVTX attack samples compared with
top-10, while only raising the corpus anomaly-window ratio from 0.0503 to
0.0511 in the runtime-like scenario.

## Main Blind Spots

- Many missed samples are too short for sequence modelling. At top-10, 183 of
  203 missed files have 20 or fewer parsed events, and 38 files have only one
  parsed event, so there is no meaningful next-event prediction window.
- OOV handling is still too tolerant in some sections. At top-10, 71 missed
  files contain unknown-template windows. If every unknown window became an
  anomaly, sample recall would rise to about 0.525, but that setting is likely
  too harsh for normal operational logs.
- Sysmon is still routed to the older Sysmon/LMD profile. In this attack corpus,
  191 files are Sysmon-profile files, so EVTX Security improvements alone cannot
  fix the whole corpus.
- Some large misses are all-unknown or near-all-unknown, for example
  `CA_PetiPotam_etw_rpc_efsr_5_6.evtx`, `bits_openvpn.evtx`, and
  `DE_1102_security_log_cleared.evtx`.

## Next Model-Centric Improvements

- Add a session-start/BOS training mode so one-event and very-short EVTX files
  can still be scored by DeepLog without heuristic fallback.
- Retrain with a lower `<UNK>` augmentation ratio. The current model learned
  that long unknown bursts can be normal, which prevents all-unknown attack
  files from surfacing.
- Keep EVTX-ATTACK-SAMPLES as validation only, not normal training data.
- Expand benign collection by provider/channel coverage, especially Security,
  PowerShell Operational, BITS, RdpCoreTS, EventLog/System, and RPC/ETW-style
  providers. The goal is to reduce accidental OOV while keeping truly rare
  attack-only event patterns suspicious.
- Train a separate Sysmon EVTX profile from Sysmon-like benign data instead of
  relying on the LMD profile.
