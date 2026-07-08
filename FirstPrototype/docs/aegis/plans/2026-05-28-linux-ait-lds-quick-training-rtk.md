# Linux AIT-LDS Quick Training RTK

## Goal

Add a Linux DeepLog profile for AIT-LDS/Kyoushi `auth.log`, `audit.log`, and `syslog` data without changing existing Windows/EVTX defaults.

## Architecture

The Linux path follows the existing DeepLog pattern:

- dataset converter writes `linux_ait_lds.log_structured.csv`
- structured CSV keeps `Timestamp`, `Label`, `EventId`, `EventTemplate`, `Content`, and `AgentName`
- deterministic Linux template helper is shared by converter and runtime parser strategy
- runtime profile is explicit as `linux_ait_lds`
- evaluator accepts `--profile linux_ait_lds`

## Tech Stack

Python, pandas, existing Drain/DeepLog runtime, existing `evaluation.deeplog_eval` CLI, existing NEWMLMODL `main_run.py`.

## Baseline/Authority Refs

- Existing profiles: `general`, `sysmon`, `windows_apt`, `lmd_enriched`, `windows_loghub`
- AIT-LDS structure: `gather` holds logs, `labels` mirrors the same paths, labels are JSONL records keyed by one-based `line`
- AIT-LDS Linux sources in scope: auth, audit, syslog

## Compatibility Boundary

Windows/EVTX defaults remain unchanged. Linux auto-selection is gated by the Linux model and vocab artifacts existing, so current general text parsing is preserved before training.

## Verification

Target tests:

```powershell
python -m unittest backend.test_linux_ait_lds_profile
python -m unittest backend.evaluation.test_deeplog_eval
python -m unittest discover -s backend -p test_template_parity_audit.py
python -m unittest backend.test_deeplog_template_enrichment
```

Verified on 2026-05-28:

- `python -m unittest backend.test_linux_ait_lds_profile` passed 4 tests
- `python -m unittest backend.evaluation.test_deeplog_eval` passed 15 tests
- `python -m unittest discover -s backend -p test_template_parity_audit.py` passed 3 tests
- `python -m unittest backend.test_deeplog_template_enrichment` passed 7 tests

Manual training smoke after dataset is available:

```powershell
python backend/tools/build_linux_ait_lds_dataset.py --input-root D:\path\to\ait-lds --output-dir D:\FAKI\NEWMLMODL\dataset\linux_ait_lds
cd D:\FAKI\NEWMLMODL
python main_run.py --config_file D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_ait_lds_quick.yaml
```

## Risks

The first quick model should be treated as profile bootstrap, not final thesis evidence, until full natural and balanced evaluation runs are saved. The training YAML uses `dataset_name: lmd2023` intentionally to reuse host-aware chronological splitting in the existing NEWMLMODL trainer.

Scenario1 attack labels appear around 56%-58% of the `intranet_server` timeline, so the quick config uses `train_size: 0.5`. This keeps training normal-only before the labelled attack burst and leaves the attack windows in evaluation.

## Scenario1 Execution Evidence

Dataset path: `D:\FAKI\DATASETLINUX\scenario1`

Converter output:

- Structured CSV: `D:\FAKI\NEWMLMODL\dataset\linux_ait_lds\linux_ait_lds.log_structured.csv`
- Rows: 90,698
- Labels: 90,667 normal, 31 attack
- Sources: 9,000 auth, 25,090 audit, 56,608 syslog
- Templates: 1,311

Training artifacts:

- Model: `D:\FAKI\NEWMLMODL\output_linux_ait_lds\lmd2023\sliding\W20_S20_CTrue_train0.5_per_host_chronological\models\DeepLog.pt`
- Vocab: `D:\FAKI\NEWMLMODL\output_linux_ait_lds\lmd2023\sliding\W20_S20_CTrue_train0.5_per_host_chronological\vocabs\DeepLog.pkl`

Cached evaluation output:

- `D:\FAKI\FirstPrototype\output\evaluation\linux_ait_lds_scenario1_cached_topk_wide`
- Natural eval top-k 200: recall 1.0, specificity 0.8678, FPR 0.1322, precision 0.0132, F1 0.0260, support 4 attack / 2,270 normal
- Balanced eval top-k 200: precision 1.0, recall 1.0, F1 1.0, support 4 attack / 4 normal

Interpretation: this is a successful bootstrap run, but not thesis-ready evidence. Natural precision is very low because scenario1 core Linux eval has only 4 positive cached windows. The next Linux pass should use label-aware trimming and/or finer attack-window generation before claiming final metrics.
