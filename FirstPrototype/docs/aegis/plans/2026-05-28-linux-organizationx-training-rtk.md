# Linux Organization-X Training RTK

## Goal

Train DeepLog on the local Organization-X dataset using an internal chronological
train/test split, then evaluate the cached natural and balanced holdout splits.

## Architecture

- Dataset source: `D:\FAKI\NEWMLMODL\dataset\linux_organizationx_all`
- Training config: `backend/tools/deeplog_linux_organizationx_quick.yaml`
- Split mode: per-host chronological
- Windowing: 20 rows, step 20
- Training policy: normal-only DeepLog training through `dataset_name: lmd2023`
- Evaluation: cached `eval.records.gz` and `balanced_eval.records.gz`

## Tech Stack

Python, pandas, existing NEWMLMODL `main_run.py`, existing
`backend.evaluation.deeplog_eval` cached evaluator.

## Baseline/Authority Refs

- DeepLog profile baseline: `docs/aegis/baseline/2026-05-28-deeplog-profile-baseline.md`
- Organization-X converter RTK: `docs/aegis/plans/2026-05-28-linux-loghub-organizationx-rtk.md`

## Compatibility Boundary

No Windows/EVTX/Sysmon defaults are changed. This run uses explicit
organization-x dataset/config/output paths.

## Verification

Commands run:

```powershell
python main_run.py --config_file D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_organizationx_quick.yaml
python -m backend.evaluation.deeplog_eval --eval-mode cached_both --cached-config D:\FAKI\FirstPrototype\backend\tools\deeplog_linux_organizationx_quick.yaml --cached-topk-values 3,5,9,14,20,40,50 --output-dir D:\FAKI\FirstPrototype\output\evaluation\linux_organizationx_cached
python -m unittest backend.test_linux_cross_dataset
python -m py_compile backend\tools\build_linux_cross_dataset.py backend\modules\linux_log_templates.py
```

All commands completed successfully on 2026-05-28.

## Split Evidence

Input rows:

- Total rows: 224,521
- Attack rows: 11,513
- Normal rows: 213,008

Trainer split:

- `organization_x_apache`: 10,960 windows, 3,495 abnormal, train 5,480, eval 5,480
- `organization_x_auth`: 217 windows, 1 abnormal, train 108, eval 109
- `organization_x_syslog`: 50 windows, 2 abnormal, train 25, eval 25
- Train after normal-only filter: 4,022 windows
- Natural eval: 5,614 windows, 3,707 normal / 1,907 abnormal
- Balanced eval: 3,814 windows, 1,907 normal / 1,907 abnormal

## Artifacts

- Model: `D:\FAKI\NEWMLMODL\output_linux_organizationx\lmd2023\sliding\W20_S20_CTrue_train0.5_per_host_chronological\models\DeepLog.pt`
  - Size: 3,353,063 bytes
- Vocab: `D:\FAKI\NEWMLMODL\output_linux_organizationx\lmd2023\sliding\W20_S20_CTrue_train0.5_per_host_chronological\vocabs\DeepLog.pkl`
  - Size: 18,072 bytes
- Cached eval report: `D:\FAKI\FirstPrototype\output\evaluation\linux_organizationx_cached`

## Natural Eval Results

Best F1 in the sweep is `topk=3`:

- Windows: 5,614
- Support: 3,696 normal / 1,918 abnormal
- Accuracy: 0.3935
- Precision: 0.2714
- Recall: 0.4604
- F1: 0.3415
- Specificity: 0.3588
- FPR: 0.6412
- Confusion: TN 1,326, FP 2,370, FN 1,035, TP 883

Default-ish `topk=14` from trainer:

- Accuracy: 0.6494
- Precision: 0.4067
- Recall: 0.0568
- F1: 0.0997
- FPR: 0.0430
- Confusion: TN 3,537, FP 159, FN 1,809, TP 109

## Balanced Eval Results

Best F1 in the sweep is `topk=3`:

- Windows: 3,814
- Support: 1,934 normal / 1,880 abnormal
- Accuracy: 0.4130
- Precision: 0.4154
- Recall: 0.4691
- F1: 0.4407
- Specificity: 0.3583
- FPR: 0.6417
- Confusion: TN 693, FP 1,241, FN 998, TP 882

## Interpretation

Organization-X internal split is better than Loghub-to-Organization-X because
the train and test vocabulary come from the same dataset. However, the model is
not yet thesis-ready: top-k 3 improves recall and F1 but false positives are
high, while higher top-k values reduce false positives by sacrificing almost all
recall. This is a usable baseline for method iteration, not a final promoted
runtime model.
