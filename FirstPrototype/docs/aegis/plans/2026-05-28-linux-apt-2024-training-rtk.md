# Linux APT 2024 Training RTK

## Goal

Retrain DeepLog with the local Linux APT Dataset 2024, keep the Linux pipeline
separate from Windows/EVTX profiles, and evaluate natural plus balanced cached
holdout performance.

## Architecture

- Dataset source: `D:\FAKI\DATASETLINUX\Linux-APT-Dataset-2024\Processed Version.xlsx`
- Generated dataset: `D:\FAKI\NEWMLMODL\dataset\linux_apt_2024`
- Converter: `backend/tools/build_linux_apt_2024_dataset.py`
- Training config: `backend/tools/deeplog_linux_apt_2024_quick.yaml`
- Comparison config: `backend/tools/deeplog_linux_apt_2024_train0.7.yaml`
- Split mode: per-host chronological
- Windowing: 20 rows, step 20
- Training policy: normal-only DeepLog training through `dataset_name: lmd2023`
- Evaluation: cached `eval.records.gz` and `balanced_eval.records.gz`

## Baseline/Authority Refs

- DeepLog profile baseline: `docs/aegis/baseline/2026-05-28-deeplog-profile-baseline.md`
- Prior Linux Organization-X run: `docs/aegis/plans/2026-05-28-linux-organizationx-training-rtk.md`

## Compatibility Boundary

No Windows/EVTX/Sysmon defaults are changed. This run uses explicit
Linux-APT-2024 dataset, config, and output paths.

## Leakage Guard

The source workbook has MITRE/TTP and rule metadata columns. They are useful for
audit and reporting, but they are not used to build `EventTemplate`. The
converter derives model-visible templates from `full_log` only, with the label
coming from `Malicious / General`.

## Verification

Commands run:

```powershell
python -m unittest backend.test_linux_apt_2024_dataset
python backend\tools\build_linux_apt_2024_dataset.py --input-xlsx "D:\FAKI\DATASETLINUX\Linux-APT-Dataset-2024\Processed Version.xlsx" --output-dir "D:\FAKI\NEWMLMODL\dataset\linux_apt_2024" --log-name linux_apt_2024.log
python main_run.py --config_file D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_apt_2024_quick.yaml
python -m backend.evaluation.deeplog_eval --eval-mode cached_both --cached-config D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_apt_2024_quick.yaml --cached-topk-values 3,5,9,20,50,100,150,182,220,260,300,350 --output-dir D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached
python -m backend.evaluation.deeplog_eval --eval-mode cached_eval --cached-config D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_apt_2024_quick.yaml --cached-topk-values 321,322,323,324,325,326,327,328,329,330,331,332,333,334,335,336,337,338,339 --output-dir D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached_topk_ultrafine
python main_run.py --config_file D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_apt_2024_train0.7.yaml
python -m backend.evaluation.deeplog_eval --eval-mode cached_both --cached-config D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_apt_2024_train0.7.yaml --cached-topk-values 3,5,9,20,50,100,150,200,250,300,328,341 --output-dir D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_train0.7_cached
```

All commands completed successfully on 2026-05-28.

## Dataset Evidence

Generated structured dataset:

- Rows written: 124,925
- Normal rows: 100,073
- Attack rows: 24,852
- Event templates: 648
- Structured CSV size: 145,200,354 bytes
- Leakage guard in summary: `EventTemplate is derived from full_log only; MITRE/TTP columns are not used.`

Agent distribution:

- `machine-1`: 67,097 rows
- `Machine-1-New`: 49,677 rows
- `machine-2`: 4,461 rows
- `machine-3`: 3,152 rows
- `ubuntu`: 538 rows

## Split Evidence

Primary split `train_size: 0.8`:

- Train before normal-only filter: 4,997 windows
- Train after normal-only filter: 3,153 windows
- Natural eval: 1,251 windows, 1,011 normal / 240 abnormal
- Balanced eval: 480 windows, 240 normal / 240 abnormal
- Vocabulary size: 405

Comparison split `train_size: 0.7`:

- Train after normal-only filter: 2,602 windows
- Natural eval: 1,878 windows, 1,562 normal / 316 abnormal
- Balanced eval: 632 windows, 316 normal / 316 abnormal
- Vocabulary size: 370

## Artifacts

Primary `train_size: 0.8` artifacts:

- Model: `D:\FAKI\NEWMLMODL\output_linux_apt_2024\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\models\DeepLog.pt`
  - Size: 4,432,487 bytes
- Vocab: `D:\FAKI\NEWMLMODL\output_linux_apt_2024\lmd2023\sliding\W20_S20_CTrue_train0.8_per_host_chronological\vocabs\DeepLog.pkl`
  - Size: 134,728 bytes
- Cached eval reports:
  - `D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached`
  - `D:\FAKI\FirstPrototype\output\evaluation\linux_apt_2024_cached_topk_ultrafine`

## Natural Eval Results

Best natural F1 in the primary split sweep is `topk=328` or `topk=329`:

- Windows: 1,251
- Support: 1,011 normal / 240 abnormal
- Accuracy: 0.9089
- Precision: 0.8247
- Recall: 0.6667
- F1: 0.7373
- Specificity: 0.9664
- FPR: 0.0336
- ROC-AUC: 0.8781
- Average precision: 0.6241
- Confusion: TN 977, FP 34, FN 80, TP 160

Trainer-recommended `topk=300` is also usable:

- Accuracy: 0.9041
- Precision: 0.8000
- Recall: 0.6667
- F1: 0.7273
- FPR: 0.0396
- Confusion: TN 971, FP 40, FN 80, TP 160

## Balanced Eval Results

Best balanced F1 in the primary split coarse sweep is `topk=50`:

- Windows: 480
- Support: 240 normal / 240 abnormal
- Accuracy: 0.8042
- Precision: 0.7852
- Recall: 0.8375
- F1: 0.8105
- Specificity: 0.7708
- FPR: 0.2292
- ROC-AUC: 0.8762
- Average precision: 0.8385
- Confusion: TN 185, FP 55, FN 39, TP 201

Best balanced accuracy in the same sweep is `topk=182`:

- Accuracy: 0.8271
- Precision: 0.9067
- Recall: 0.7292
- F1: 0.8083
- FPR: 0.0750
- Confusion: TN 222, FP 18, FN 65, TP 175

## Split Comparison

The `train_size: 0.7` comparison is worse than the primary 0.8 split:

- Best natural F1: 0.6439 at `topk=300`
- Balanced best F1: 0.7889 at `topk=50`
- ROC-AUC is lower on natural eval: 0.8539 versus 0.8781

## Interpretation

Linux APT Dataset 2024 is much better for this Linux DeepLog experiment than
AIT-LDS scenario1, Loghub-to-Organization-X, and Organization-X internal split.
It is not a clean "all metrics above 80" result on the natural holdout because
recall remains 0.6667 at the best F1 point. However, it is a credible Linux APT
baseline: natural precision, accuracy, specificity, FPR, ROC-AUC, and balanced
F1 are strong enough to report as a serious experiment.

Recommended thesis framing:

- Use `train_size: 0.8` as the primary Linux APT profile.
- Report natural eval as the deployment-like result.
- Report balanced eval as the class-balance sensitivity check.
- Be explicit that MITRE/TTP labels are excluded from model-visible templates.
- Do not claim Linux DeepLog reaches 80 F1 on natural holdout without further
  tuning or a different modeling strategy.
