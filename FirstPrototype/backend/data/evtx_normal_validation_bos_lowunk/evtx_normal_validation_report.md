# EVTX Normal Validation Report

Normal EVTX root: `D:\FAKI\SecurityAuditNormalCorpus`
Structured normal sample: `D:\FAKI\NEWMLMODL\dataset\windows_evtx_bos_lowunk\windows_evtx_bos_lowunk.log_structured.csv`

## Top-K Normal Sweep

| Top-K | Sources | Flagged Sources | Windows | Anomalies | Anomaly Window Ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| 3 | 49 | 49 | 2119 | 248 | 0.1170 |
| 5 | 49 | 44 | 2119 | 134 | 0.0632 |
| 10 | 49 | 35 | 2119 | 72 | 0.0340 |
| 14 | 49 | 29 | 2119 | 41 | 0.0193 |

## Source Split

| Top-K | Source Kind | Sources | Flagged Sources | Windows | Anomalies | Anomaly Window Ratio |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 3 | raw_evtx | 1 | 1 | 287 | 4 | 0.0139 |
| 3 | structured_normal_sample | 48 | 48 | 1832 | 244 | 0.1332 |
| 5 | raw_evtx | 1 | 1 | 287 | 2 | 0.0070 |
| 5 | structured_normal_sample | 48 | 43 | 1832 | 132 | 0.0721 |
| 10 | raw_evtx | 1 | 1 | 287 | 1 | 0.0035 |
| 10 | structured_normal_sample | 48 | 34 | 1832 | 71 | 0.0388 |
| 14 | raw_evtx | 1 | 1 | 287 | 1 | 0.0035 |
| 14 | structured_normal_sample | 48 | 28 | 1832 | 40 | 0.0218 |

## Raw EVTX at Top-5

| Source | Parsed Events | Templates | Windows | Anomalies | Anomaly Window Ratio | Unknown Windows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `D:\FAKI\SecurityAuditNormalCorpus\security_audit_normal.evtx` | 287 | 6 | 287 | 2 | 0.0070 | 0 |

## Top Normal Anomaly Events at Top-5

| Event | Count |
| --- | ---: |
| `EventID 4634 Provider Microsoft-Windows-Security-Auditing Channel Security` | 9 |
| `EventID 7036 Provider Service Control Manager Channel System` | 8 |
| `EventID 4776 Provider Microsoft-Windows-Security-Auditing Channel Security` | 7 |
| `EventID 7040 Provider Service Control Manager Channel System` | 7 |
| `EventID 16384 Provider Microsoft-Windows-Security-SPP Channel Application` | 6 |
| `<UNK>` | 6 |
| `EventID 8224 Provider VSS Channel Application` | 6 |
| `EventID 7009 Provider Service Control Manager Channel System` | 6 |
| `EventID 1014 Provider Microsoft-Windows-DNS-Client Channel System` | 6 |
| `EventID 1001 Provider Windows Error Reporting Channel Application` | 6 |
| `EventID 5156 Provider Microsoft-Windows-Security-Auditing Channel Security` | 5 |
| `EventID 4616 Provider Microsoft-Windows-Security-Auditing Channel Security` | 5 |

## Worst Normal Sources at Top-5

| Source Kind | Source | Windows | Anomalies | Anomaly Window Ratio |
| --- | --- | ---: | ---: | ---: |
| structured_normal_sample | `windows_apt_benign:DESKTOP-DS4FBF4#session000006` | 40 | 8 | 0.2000 |
| structured_normal_sample | `windows_apt_benign:agent1#session000000` | 40 | 8 | 0.2000 |
| structured_normal_sample | `windows_apt_benign:agent1#session000001` | 40 | 8 | 0.2000 |
| structured_normal_sample | `windows_apt_benign:DESKTOP-DS4FBF4#session000005` | 40 | 7 | 0.1750 |
| structured_normal_sample | `windows_apt_benign:DESKTOP-DS4FBF4#session000007` | 40 | 7 | 0.1750 |
| structured_normal_sample | `windows_apt_benign:agent1#session000007` | 40 | 7 | 0.1750 |
| structured_normal_sample | `normal_security_evtx:Pluto_6#session000007` | 7 | 1 | 0.1429 |
| structured_normal_sample | `windows_apt_benign:DESKTOP-DS4FBF4#session000008` | 29 | 4 | 0.1379 |

## Interpretation

Top-5 is still the best runtime default for the current EVTX Security profile.
It keeps the raw normal EVTX anomaly rate low while preserving the attack-corpus gain from the BOS low-UNK model.
Relaxing to Top-10 or Top-14 lowers normal noise, but it also removes too much attack signal from Windows Security EVTX samples.

The structured normal samples are intentionally more diverse than the single raw normal EVTX file, so they are useful as a noise stress test rather than a direct production false-positive estimate.
