# EVTX BOS Low-UNK Validation Report

Validation root: `D:\FAKI\LogADEmpirical-dev\EVTX-ATTACK-SAMPLES`

Model artifacts:

- `D:\FAKI\NEWMLMODL\output_windows_evtx_bos_lowunk\windows_apt\sliding\W30_S1_CTrue_train0.8_per_host_chronological\models\DeepLog.pt`
- `D:\FAKI\NEWMLMODL\output_windows_evtx_bos_lowunk\windows_apt\sliding\W30_S1_CTrue_train0.8_per_host_chronological\vocabs\DeepLog.pkl`

Dataset:

- `D:\FAKI\NEWMLMODL\dataset\windows_evtx_bos_lowunk`
- Rows: `804205`
- BOS rows: `268520`
- Pseudo-sessions: `13426`
- UNK rows: `4379`

## Top-K Sweep

| Top-K | Detected Files | Missed Files | Sample Recall | Anomaly Window Ratio |
| --- | ---: | ---: | ---: | ---: |
| 3 | 167 / 278 | 111 | 0.6007 | 0.0925 |
| 5 | 152 / 278 | 126 | 0.5468 | 0.0840 |
| 10 | 90 / 278 | 188 | 0.3237 | 0.0404 |
| 14 | 89 / 278 | 189 | 0.3201 | 0.0326 |

## Runtime-Like Comparison

| Scenario | Detected Files | Sample Recall | Anomaly Window Ratio |
| --- | ---: | ---: | ---: |
| Previous: Sysmon top-3 + Windows APT top-5 | 116 / 278 | 0.4173 | 0.0511 |
| BOS low-UNK: Sysmon top-3 + Windows APT top-5 | 167 / 278 | 0.6007 | 0.0898 |

## Profile Split

| Profile | Detected Files | Sample Recall |
| --- | ---: | ---: |
| Sysmon | 83 / 191 | 0.4346 |
| Windows APT / Security EVTX | 84 / 87 | 0.9655 |

## Important Spot Checks

- `Discovery\dicovery_4661_net_group_domain_admins_target.evtx`: detected, `18` anomaly windows. Now includes `4661` and `1102`.
- `Defense Evasion\DE_1102_security_log_cleared.evtx`: detected, `14` anomaly windows. Includes `1102`.
- `Credential Access\4794_DSRM_password_change_t1098.evtx`: detected even though the file has only `1` event.
- `Credential Access\CA_PetiPotam_etw_rpc_efsr_5_6.evtx`: detected, although still mostly unknown-template context.
- `Command and Control\bits_openvpn.evtx`: detected.

## Interpretation

The BOS/low-UNK change solved the main Windows Security EVTX gap: short files
and all-unknown bursts no longer silently pass as normal. The remaining corpus
misses are mostly Sysmon-profile files, which still use the older Sysmon/LMD
model and should be handled by a separate Sysmon EVTX retraining pass.

The BOS model checkpoint was saved successfully. The original training process
hung during the final evaluation stage after saving the model, so corpus
validation was run directly against the saved checkpoint.
