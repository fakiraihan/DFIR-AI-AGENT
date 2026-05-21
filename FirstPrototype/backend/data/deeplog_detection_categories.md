# DeepLog Detection Categories

## Overview

This document describes the detection categories used by the `DeepLogDetector` in the `FirstPrototype` backend. These categories distinguish between pure ML-based sequence anomalies and various fallback or unknown-template conditions.

## Detection Categories

| Category | Source | Meaning | Confidence Semantics | Recommended Consumer Wording |
| :--- | :--- | :--- | :--- | :--- |
| `deeplog_topk_miss` | DeepLog Model | The actual event template was not found in the top-k predicted event templates for the current window. | **High (Sequence)**: Indicates a behavioral deviation from the learned normal baseline. | "Behavioral sequence deviation", "Unexpected event following known sequence" |
| `unknown_template` | Parsing / Vocab | An individual event template in the window was not found in the training vocabulary. | **Low (Unknown)**: The model cannot evaluate this specific event. | "Observation of previously unseen event type", "Unknown log pattern" |
| `unknown_template_ratio_exceeded` | Configuration | The proportion of unknown event templates in the window exceeded `deeplog_max_unknown_ratio`. | **Low (Unknown)**: Too much of the window is unknown for reliable DeepLog evaluation. | "High density of unknown event patterns", "Unreliable sequence context" |
| `evtx_sparse_fallback` | Sparse EVTX Heuristic | The log contains too few events for a full DeepLog window, but suspicious command/process indicators were found. | **Medium (Heuristic)**: Not a sequence prediction, but a field-level suspicious indicator. | "Suspicious activity in short event burst", "Heuristic-based suspicious indicator" |

## Important Guardrails

- **Not Proof of Attack**: `unknown_template`, `unknown_template_ratio_exceeded`, and `evtx_sparse_fallback` detections are **not** proof of DeepLog learned attack behavior.
- **Reporting**: These statuses should not be reported as "ML Confidence" or "Model Accuracy" improvements. They are safety and coverage mechanisms.
- **Sequence Confidence**: Only `deeplog_topk_miss` represents a deviation from the model's learned sequence probability distribution.

## Configuration Parameters

The following parameters in `backend/config.py` control these behaviors:

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `deeplog_unknown_template_mode` | `"ignore"` | Determines how unknown templates are handled: `ignore` (skip), `warn` (mark but don't flag as anomaly), `anomaly` (flag as anomaly). |
| `deeplog_evtx_sparse_fallback_enabled` | `True` | Enables the heuristic fallback for short EVTX logs that don't meet the `deeplog_window_size`. |
| `deeplog_evtx_sparse_fallback_threshold` | `0.75` | The threshold for the sparse fallback heuristic score to trigger an anomaly. |
| `deeplog_max_unknown_ratio` | `0.4` | The maximum allowable ratio of unknown templates in a window before it is marked as `unknown_template_ratio_exceeded`. |
| `deeplog_skip_unknown_windows` | `True` | Legacy parameter; if `True`, sets `deeplog_unknown_template_mode` to `ignore` if not explicitly set. |

## Service Summaries

Detection results are summarized in the `orchestrator_service` and `analyze_service` using `evaluation_status_counts`. Consumers should look for these counts to understand the distribution of detection reasons in an investigation session.
