"""Audit EVTX attack samples against the current parser/model pipeline.

The output is a compact CSV coverage map: profile selected, event volume,
DeepLog/heuristic statuses, and the strongest fallback reasons per sample.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from config import settings  # noqa: E402
from modules.anomaly import detect_anomalies_in_logs  # noqa: E402
from services.parsing_service import parse_with_profile  # noqa: E402


DEFAULT_ROOT = Path(r"D:\FAKI\LogADEmpirical-dev\EVTX-ATTACK-SAMPLES")
DEFAULT_OUTPUT = BACKEND_DIR / "data" / "evtx_attack_corpus_audit.csv"


def _status_counts(results_df) -> dict[str, int]:
    if results_df.empty or "evaluation_status" not in results_df.columns:
        return {}
    return {
        str(key): int(value)
        for key, value in results_df["evaluation_status"].value_counts().to_dict().items()
    }


def _reason_counts(anomalies_df) -> dict[str, int]:
    counter: Counter[str] = Counter()
    if anomalies_df.empty or "fallback_reasons" not in anomalies_df.columns:
        return {}

    for value in anomalies_df["fallback_reasons"].tolist():
        reasons: list[Any]
        if isinstance(value, list):
            reasons = value
        elif isinstance(value, str):
            try:
                parsed = json.loads(value)
                reasons = parsed if isinstance(parsed, list) else [value]
            except Exception:
                reasons = [value]
        else:
            reasons = []
        counter.update(str(reason) for reason in reasons if reason)
    return dict(counter.most_common(12))


def _unknown_window_count(results_df, status_counts: dict[str, int]) -> int:
    if not results_df.empty and "unknown_count" in results_df.columns:
        return int((results_df["unknown_count"] > 0).sum())
    return sum(
        status_counts.get(status, 0)
        for status in ("unknown_template", "unknown_template_ratio_exceeded")
    )


def audit_file(path: Path, root: Path, mode: str) -> dict[str, Any]:
    parsed_df, templates, profile = parse_with_profile(str(path), settings)
    results_df, anomalies_df = detect_anomalies_in_logs(
        parsed_df,
        str(profile["model_path"]),
        str(profile["vocab_path"]),
        window_size=profile["window_size"],
        step_size=settings.deeplog_step_size,
        topk=profile.get("topk", settings.deeplog_topk),
        skip_unknown_windows=settings.deeplog_skip_unknown_windows,
        max_unknown_ratio=settings.deeplog_max_unknown_ratio,
        unknown_template_mode=settings.deeplog_unknown_template_mode,
        evtx_sparse_fallback_enabled=settings.deeplog_evtx_sparse_fallback_enabled,
        evtx_sparse_fallback_threshold=settings.deeplog_evtx_sparse_fallback_threshold,
        template_similarity_enabled=settings.deeplog_template_similarity_enabled,
        template_similarity_threshold=settings.deeplog_template_similarity_threshold,
        use_bos_context=profile.get("use_bos_context", False),
        bos_token=profile.get("bos_token", "<BOS>"),
        bos_count=profile.get("bos_count"),
    )
    status_counts = _status_counts(results_df)
    reason_counts = _reason_counts(anomalies_df)
    windows = len(results_df)
    unknown_windows = _unknown_window_count(results_df, status_counts)
    heuristic_windows = status_counts.get("evtx_heuristic_boost", 0)
    sequence_windows = status_counts.get("deeplog_topk_miss", 0)

    return {
        "mode": mode,
        "section": path.parent.name,
        "file_name": path.name,
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "profile": profile["name"],
        "template_strategy": profile["template_strategy"],
        "topk": profile.get("topk", settings.deeplog_topk),
        "unknown_template_mode": settings.deeplog_unknown_template_mode,
        "evtx_sparse_fallback_enabled": settings.deeplog_evtx_sparse_fallback_enabled,
        "parsed_events": len(parsed_df),
        "templates": len(templates),
        "windows": windows,
        "anomalies": len(anomalies_df),
        "sequence_anomalies": sequence_windows,
        "heuristic_anomalies": heuristic_windows,
        "unknown_windows": unknown_windows,
        "unknown_ratio": round(unknown_windows / windows, 4) if windows else 0.0,
        "status_counts": json.dumps(status_counts, sort_keys=True),
        "top_fallback_reasons": json.dumps(reason_counts, sort_keys=True),
        "relative_path": str(path.relative_to(root)),
    }


def apply_audit_mode(mode: str) -> None:
    if mode == "settings":
        return
    if mode == "deeplog":
        settings.deeplog_unknown_template_mode = "evaluate"
        settings.deeplog_evtx_sparse_fallback_enabled = False
        settings.evtx_general_deeplog_profile = "general"
        settings.parser_template_strategy = "provider_eventid"
        settings.deeplog_template_similarity_enabled = False
        return
    if mode == "deeplog-windows-apt":
        settings.deeplog_unknown_template_mode = "evaluate"
        settings.deeplog_evtx_sparse_fallback_enabled = False
        settings.evtx_general_deeplog_profile = "windows_apt"
        settings.deeplog_template_similarity_enabled = True
        return
    if mode == "hybrid-old":
        settings.deeplog_unknown_template_mode = "warn"
        settings.deeplog_evtx_sparse_fallback_enabled = True
        settings.evtx_general_deeplog_profile = "general"
        settings.parser_template_strategy = "drain"
        settings.deeplog_template_similarity_enabled = False
        return
    raise ValueError(f"Unsupported audit mode: {mode}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument(
        "--mode",
        choices=("settings", "deeplog", "deeplog-windows-apt", "hybrid-old"),
        default="settings",
        help="settings=current config, deeplog=canonical OOV/no-heuristic, deeplog-windows-apt=conservative canonical profile, hybrid-old=pre-canonical heuristic fallback",
    )
    args = parser.parse_args()

    apply_audit_mode(args.mode)

    root = args.root.resolve()
    output = args.output.resolve()
    paths = sorted(root.rglob("*.evtx"))
    if args.limit > 0:
        paths = paths[: args.limit]

    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "mode",
        "section",
        "file_name",
        "path",
        "size_bytes",
        "profile",
        "template_strategy",
        "topk",
        "unknown_template_mode",
        "evtx_sparse_fallback_enabled",
        "parsed_events",
        "templates",
        "windows",
        "anomalies",
        "sequence_anomalies",
        "heuristic_anomalies",
        "unknown_windows",
        "unknown_ratio",
        "status_counts",
        "top_fallback_reasons",
        "relative_path",
    ]

    rows: list[dict[str, Any]] = []
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for index, path in enumerate(paths, start=1):
            print(f"[{index}/{len(paths)}] {path}", flush=True)
            try:
                row = audit_file(path, root, args.mode)
            except Exception as exc:
                row = {
                    "mode": args.mode,
                    "section": path.parent.name,
                    "file_name": path.name,
                    "path": str(path),
                    "size_bytes": path.stat().st_size if path.exists() else 0,
                    "profile": "error",
                    "template_strategy": "",
                    "topk": 0,
                    "unknown_template_mode": settings.deeplog_unknown_template_mode,
                    "evtx_sparse_fallback_enabled": settings.deeplog_evtx_sparse_fallback_enabled,
                    "parsed_events": 0,
                    "templates": 0,
                    "windows": 0,
                    "anomalies": 0,
                    "sequence_anomalies": 0,
                    "heuristic_anomalies": 0,
                    "unknown_windows": 0,
                    "unknown_ratio": 0.0,
                    "status_counts": json.dumps({"error": str(exc)}),
                    "top_fallback_reasons": "{}",
                    "relative_path": str(path.relative_to(root)),
                }
            rows.append(row)
            writer.writerow(row)

    total_anomalies = sum(int(row["anomalies"]) for row in rows)
    zero_anomaly = sum(1 for row in rows if int(row["anomalies"]) == 0)
    print(f"wrote: {output}")
    print(f"files: {len(rows)} anomalies_total: {total_anomalies} zero_anomaly_files: {zero_anomaly}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
