# Linux Loghub to Organization-X RTK

## Goal

Run a quick cross-dataset Linux DeepLog experiment: train on local Loghub
`Linux_2k.log` and evaluate on the local `D:\FAKI\DATASETLINUX\ADF LINUX\organization-x`
labelled dataset.

## Architecture

- Loghub is converted into `linux_loghub.log_structured.csv` as normal-only training data.
- Organization-X is converted into labelled structured CSVs using its YAML ground-truth rules.
- Linux auth/syslog templates reuse `backend/modules/linux_log_templates.py`.
- Apache access/error logs use deterministic low-cardinality Apache templates in
  `backend/tools/build_linux_cross_dataset.py`.
- Existing Windows/EVTX profiles remain unchanged.

## Tech Stack

Python, pandas, gzip, existing NEWMLMODL `main_run.py`, existing
`backend.evaluation.deeplog_eval` CLI.

## Baseline/Authority Refs

- DeepLog profile baseline: `docs/aegis/baseline/2026-05-28-deeplog-profile-baseline.md`
- Prior Linux AIT-LDS RTK: `docs/aegis/plans/2026-05-28-linux-ait-lds-quick-training-rtk.md`

## Compatibility Boundary

No existing Windows, EVTX, Sysmon, or AIT-LDS runtime default is replaced. The
Loghub experiment is run through explicit dataset/config/artifact paths.

## Verification

Unit tests:

```powershell
python -m unittest backend.test_linux_cross_dataset
python -m unittest backend.test_linux_ait_lds_profile
```

Both passed on 2026-05-28 after adding Loghub PAM process-name handling.

## Execution Evidence

Local inputs:

- Loghub: `D:\FAKI\DATASETLINUX\LOGHUB\Linux_2k.log`
- Organization-X: `D:\FAKI\DATASETLINUX\ADF LINUX\organization-x`

Generated datasets:

- `D:\FAKI\NEWMLMODL\dataset\linux_loghub\linux_loghub.log_structured.csv`
  - 2,000 rows
  - 2,000 normal / 0 attack
  - 139 templates
  - 849 auth, 1,151 syslog
- `D:\FAKI\NEWMLMODL\dataset\linux_organizationx_auth_syslog\linux_organizationx_auth_syslog.log_structured.csv`
  - 5,332 rows
  - 5,328 normal / 4 attack
  - 37 templates
- `D:\FAKI\NEWMLMODL\dataset\linux_organizationx_all\linux_organizationx_all.log_structured.csv`
  - 224,521 rows
  - 213,008 normal / 11,513 attack
  - 87 templates

Training config:

- `backend/tools/deeplog_linux_loghub_quick.yaml`

Training artifacts:

- Model: `D:\FAKI\NEWMLMODL\output_linux_loghub\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\models\DeepLog.pt`
- Vocab: `D:\FAKI\NEWMLMODL\output_linux_loghub\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\vocabs\DeepLog.pkl`

Evaluation outputs:

- Auth/syslog sweep: `D:\FAKI\FirstPrototype\output\evaluation\linux_loghub_to_organizationx_auth_syslog`
- All-source partial top-k 3: `D:\FAKI\FirstPrototype\output\evaluation\linux_loghub_to_organizationx_all\topk_3`

## Results

Auth/syslog, all top-k values 3/5/9/20/36:

- Windows: 266
- Support: 3 attack / 263 normal
- Precision: 0.0113
- Recall: 1.0000
- F1: 0.0223
- FPR: 1.0000
- Specificity: 0.0000
- Confusion: TN 0, FP 263, FN 0, TP 3

All-source top-k 3:

- Windows: 11,226
- Support: 3,639 attack / 7,587 normal
- Precision: 0.3242
- Recall: 1.0000
- F1: 0.4896
- FPR: 1.0000
- Specificity: 0.0000
- Confusion: TN 0, FP 7,587, FN 0, TP 3,639

Template overlap audit:

- Auth/syslog test rows with templates present in full Loghub CSV templates: 1 / 5,332
- All-source test rows with templates present in full Loghub CSV templates: 1 / 224,521

## Interpretation

This experiment is technically successful but not a viable performance result.
Loghub Linux and Organization-X have almost no shared event-template vocabulary,
so the model behaves as a novelty detector that flags nearly every external
window. This gives perfect recall only because specificity collapses to zero.

The better next experiment is to train on normal-only Organization-X segments
and test on labelled Organization-X holdout, or choose another labelled auth/log
dataset whose normal template vocabulary overlaps with Loghub.
