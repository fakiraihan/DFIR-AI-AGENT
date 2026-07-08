# EVTX Normal Validation Report

Normal EVTX root: `D:\FAKI\SecurityAuditNormalCorpus`
Structured normal sample: `D:\FAKI\NEWMLMODL\dataset\windows_evtx_bos_lowunk\windows_evtx_bos_lowunk.log_structured.csv`

## Top-K Normal Sweep

| Top-K | Sources | Flagged Sources | Windows | Anomalies | Anomaly Window Ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 16 | 16 | 843 | 292 | 0.3464 |
| 3 | 16 | 16 | 843 | 64 | 0.0759 |
| 5 | 16 | 16 | 843 | 40 | 0.0474 |
| 9 | 16 | 15 | 843 | 26 | 0.0308 |

## Source Split

| Top-K | Source Kind | Sources | Flagged Sources | Windows | Anomalies | Anomaly Window Ratio |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | raw_evtx | 1 | 1 | 287 | 94 | 0.3275 |
| 1 | structured_normal_sample | 15 | 15 | 556 | 198 | 0.3561 |
| 3 | raw_evtx | 1 | 1 | 287 | 4 | 0.0139 |
| 3 | structured_normal_sample | 15 | 15 | 556 | 60 | 0.1079 |
| 5 | raw_evtx | 1 | 1 | 287 | 2 | 0.0070 |
| 5 | structured_normal_sample | 15 | 15 | 556 | 38 | 0.0683 |
| 9 | raw_evtx | 1 | 1 | 287 | 1 | 0.0035 |
| 9 | structured_normal_sample | 15 | 14 | 556 | 25 | 0.0450 |

## Raw EVTX at Top-5

| Source | Parsed Events | Templates | Windows | Anomalies | Anomaly Window Ratio | Unknown Windows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `D:\FAKI\SecurityAuditNormalCorpus\security_audit_normal.evtx` | 287 | 6 | 287 | 2 | 0.0070 | 0 |

## Top Normal Anomaly Events at Top-5

| Event | Count |
| --- | ---: |
| `EventID 4634 Provider Microsoft-Windows-Security-Auditing Channel Security` | 5 |
| `EventID 7036 Provider Service Control Manager Channel System` | 4 |
| `EventID 5156 Provider Microsoft-Windows-Security-Auditing Channel Security` | 3 |
| `EventID 16384 Provider Microsoft-Windows-Security-SPP Channel Application` | 3 |
| `EventID 5158 Provider Microsoft-Windows-Security-Auditing Channel Security` | 3 |
| `EventID 4616 Provider Microsoft-Windows-Security-Auditing Channel Security` | 3 |
| `EventID 5140 Provider Microsoft-Windows-Security-Auditing Channel Security` | 2 |
| `EventID 7040 Provider Service Control Manager Channel System` | 2 |
| `EventID 255 Provider Microsoft-Windows-Sysmon Channel Microsoft-Windows-Sysmon/Operational` | 2 |
| `EventID 7009 Provider Service Control Manager Channel System` | 2 |
| `EventID 8198 Provider Microsoft-Windows-Security-SPP Channel Application` | 1 |
| `EventID 900 Provider Microsoft-Windows-Security-SPP Channel Application` | 1 |

## Worst Normal Sources at Top-5

| Source Kind | Source | Windows | Anomalies | Anomaly Window Ratio |
| --- | --- | ---: | ---: | ---: |
| structured_normal_sample | `czmuni_winlog:10.7.101.14#session000000` | 40 | 5 | 0.1250 |
| structured_normal_sample | `windows_apt_benign:DESKTOP-DS4FBF4#session000003` | 40 | 5 | 0.1250 |
| structured_normal_sample | `czmuni_winlog:10.7.101.14#session000001` | 24 | 3 | 0.1250 |
| structured_normal_sample | `windows_apt_benign:DESKTOP-DS4FBF4#session000000` | 40 | 4 | 0.1000 |
| structured_normal_sample | `windows_apt_benign:DESKTOP-DS4FBF4#session000004` | 40 | 4 | 0.1000 |
| structured_normal_sample | `czmuni_winlog:10.7.100.117#session000001` | 12 | 1 | 0.0833 |
| structured_normal_sample | `czmuni_winlog:10.7.100.117#session000000` | 40 | 3 | 0.0750 |
| structured_normal_sample | `windows_apt_benign:DESKTOP-DS4FBF4#session000001` | 40 | 3 | 0.0750 |

## Interpretation

Top-5 is still the best runtime default for the current EVTX Security profile.
It keeps the raw normal EVTX anomaly rate low while preserving the attack-corpus gain from the BOS low-UNK model.
Relaxing to Top-10 or Top-14 lowers normal noise, but it also removes too much attack signal from Windows Security EVTX samples.

The structured normal samples are intentionally more diverse than the single raw normal EVTX file, so they are useful as a noise stress test rather than a direct production false-positive estimate.
