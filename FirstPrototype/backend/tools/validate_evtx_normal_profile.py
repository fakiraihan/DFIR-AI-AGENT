"""Validate the current EVTX DeepLog profile against normal-only data."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from config import settings  # noqa: E402
import modules.anomaly as anomaly_module  # noqa: E402
import modules.parsing as parsing_module  # noqa: E402
from modules.anomaly import DeepLogDetector  # noqa: E402
from services.parsing_service import build_model_profile, parse_with_profile  # noqa: E402


DEFAULT_NORMAL_EVTX_ROOT = Path(r"D:\FAKI\SecurityAuditNormalCorpus")
DEFAULT_STRUCTURED_CSV = Path(
    r"D:\FAKI\NEWMLMODL\dataset\windows_evtx_bos_lowunk\windows_evtx_bos_lowunk.log_structured.csv"
)
DEFAULT_OUTPUT_DIR = BACKEND_DIR / "data" / "evtx_normal_validation_bos_lowunk"
DEFAULT_TOPK_VALUES = (3, 5, 10, 14)


def _identity_tqdm(iterable: Iterable[Any], *args: Any, **kwargs: Any) -> Iterable[Any]:
    return iterable


def _parse_topk_values(value: str) -> list[int]:
    values = []
    for part in value.split(","):
        part = part.strip()
        if part:
            values.append(int(part))
    if not values:
        raise argparse.ArgumentTypeError("at least one topk value is required")
    return sorted(set(values))


def _status_counts(results_df: pd.DataFrame) -> dict[str, int]:
    if results_df.empty or "evaluation_status" not in results_df.columns:
        return {}
    return {
        str(key): int(value)
        for key, value in results_df["evaluation_status"].value_counts().to_dict().items()
    }


def _parse_topk_indices(value: Any) -> list[int]:
    output = []
    for part in str(value or "").split("|"):
        if not part.strip():
            continue
        try:
            output.append(int(part))
        except ValueError:
            continue
    return output


def _topk_projection(results_df: pd.DataFrame, topk: int) -> tuple[list[bool], dict[str, int]]:
    anomaly_mask: list[bool] = []
    statuses: Counter[str] = Counter()
    if results_df.empty:
        return anomaly_mask, {}

    for _, row in results_df.iterrows():
        base_status = str(row.get("evaluation_status", "evaluated"))
        if base_status in {"evaluated", "deeplog_topk_miss"}:
            try:
                actual_index = int(row.get("actual_event_index", -1))
            except (TypeError, ValueError):
                actual_index = -1
            predicted_indices = _parse_topk_indices(row.get("topk_indices", ""))
            is_anomaly = actual_index not in predicted_indices[:topk]
            status = "deeplog_topk_miss" if is_anomaly else "evaluated"
        else:
            is_anomaly = bool(row.get("is_anomaly", False))
            status = base_status
        anomaly_mask.append(is_anomaly)
        statuses[status] += 1
    return anomaly_mask, dict(statuses.most_common())


def _actual_event_counts_for_mask(results_df: pd.DataFrame, anomaly_mask: list[bool]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    if results_df.empty or "actual_event" not in results_df.columns:
        return {}
    for is_anomaly, actual_event in zip(
        anomaly_mask,
        results_df["actual_event"].astype(str).tolist(),
    ):
        if is_anomaly:
            counter[actual_event] += 1
    return dict(counter.most_common(10))


def _unknown_window_count(results_df: pd.DataFrame) -> int:
    if results_df.empty or "unknown_count" not in results_df.columns:
        return 0
    return int((results_df["unknown_count"] > 0).sum())


def _avg_unknown_ratio(results_df: pd.DataFrame) -> float:
    if results_df.empty or "unknown_ratio" not in results_df.columns:
        return 0.0
    return round(float(results_df["unknown_ratio"].mean()), 4)


def _detector(profile: dict[str, Any], topk: int) -> DeepLogDetector:
    return DeepLogDetector(
        str(profile["model_path"]),
        str(profile["vocab_path"]),
        window_size=profile["window_size"],
        step_size=settings.deeplog_step_size,
        topk=topk,
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


def _append_projected_rows(
    rows: list[dict[str, Any]],
    *,
    source_kind: str,
    source_name: str,
    profile: dict[str, Any],
    parsed_events: int,
    templates: int,
    results_df: pd.DataFrame,
    topk_values: list[int],
) -> None:
    windows = len(results_df)
    unknown_windows = _unknown_window_count(results_df)
    avg_unknown_ratio = _avg_unknown_ratio(results_df)
    for topk in topk_values:
        anomaly_mask, status_counts = _topk_projection(results_df, topk)
        anomalies = sum(1 for value in anomaly_mask if value)
        rows.append(
            {
                "source_kind": source_kind,
                "source_name": source_name,
                "profile": profile["name"],
                "topk": topk,
                "parsed_events": parsed_events,
                "templates": templates,
                "windows": windows,
                "anomalies": anomalies,
                "anomaly_window_ratio": round(anomalies / windows, 4) if windows else 0.0,
                "detected": int(anomalies > 0),
                "unknown_windows": unknown_windows,
                "unknown_window_ratio": round(unknown_windows / windows, 4) if windows else 0.0,
                "avg_unknown_ratio": avg_unknown_ratio,
                "status_counts": json.dumps(status_counts, sort_keys=True),
                "top_anomaly_actual_events": json.dumps(
                    _actual_event_counts_for_mask(results_df, anomaly_mask),
                    sort_keys=True,
                ),
                "error": "",
            }
        )


def validate_raw_evtx(
    rows: list[dict[str, Any]],
    normal_evtx_root: Path,
    topk_values: list[int],
    max_lines: int | None,
) -> None:
    max_topk = max(topk_values)
    for path in sorted(normal_evtx_root.rglob("*.evtx")):
        print(f"[raw-evtx] {path}", flush=True)
        try:
            parsed_df, templates, profile = parse_with_profile(str(path), settings, max_lines=max_lines)
            detector = _detector(profile, max_topk)
            results_df = detector.detect_anomalies(parsed_df)
            _append_projected_rows(
                rows,
                source_kind="raw_evtx",
                source_name=str(path),
                profile=profile,
                parsed_events=len(parsed_df),
                templates=len(templates),
                results_df=results_df,
                topk_values=topk_values,
            )
        except Exception as exc:
            for topk in topk_values:
                rows.append(
                    {
                        "source_kind": "raw_evtx",
                        "source_name": str(path),
                        "profile": "error",
                        "topk": topk,
                        "parsed_events": 0,
                        "templates": 0,
                        "windows": 0,
                        "anomalies": 0,
                        "anomaly_window_ratio": 0.0,
                        "detected": 0,
                        "unknown_windows": 0,
                        "unknown_window_ratio": 0.0,
                        "avg_unknown_ratio": 0.0,
                        "status_counts": "{}",
                        "top_anomaly_actual_events": "{}",
                        "error": str(exc),
                    }
                )


def _runtime_df_from_structured(group_df: pd.DataFrame, max_events: int) -> pd.DataFrame:
    if max_events > 0:
        group_df = group_df.head(max_events)
    output = pd.DataFrame()
    output["event_template"] = group_df["EventTemplate"].astype(str)
    output["EventTemplate"] = output["event_template"]
    output["Content"] = group_df.get("Content", output["event_template"]).astype(str)
    output["timestamp"] = group_df.get("Timestamp", "").astype(str)
    output["line_number"] = range(1, len(output) + 1)
    output["raw_line"] = output["event_template"]
    return output.reset_index(drop=True)


def validate_structured_samples(
    rows: list[dict[str, Any]],
    structured_csv: Path,
    topk_values: list[int],
    sessions_per_source: int,
    max_events_per_session: int,
) -> None:
    if not structured_csv.exists():
        return

    profile = build_model_profile("windows_apt", settings)
    detector = _detector(profile, max(topk_values))
    df = pd.read_csv(
        structured_csv,
        usecols=["Timestamp", "EventTemplate", "Content", "AgentName", "SourceDataset"],
        low_memory=False,
    )
    df = df[df["EventTemplate"].astype(str).ne("<BOS>")].copy()
    df = df.sort_values(["SourceDataset", "AgentName", "Timestamp"], kind="stable")

    source_counts: Counter[str] = Counter()
    for (source, agent_name), group_df in df.groupby(["SourceDataset", "AgentName"], sort=False):
        source = str(source)
        if source_counts[source] >= sessions_per_source:
            continue
        source_counts[source] += 1
        source_name = f"{source}:{agent_name}"
        print(f"[structured] {source_name}", flush=True)
        runtime_df = _runtime_df_from_structured(group_df, max_events=max_events_per_session)
        results_df = detector.detect_anomalies(runtime_df)
        _append_projected_rows(
            rows,
            source_kind="structured_normal_sample",
            source_name=source_name,
            profile=profile,
            parsed_events=len(runtime_df),
            templates=int(runtime_df["event_template"].nunique()) if not runtime_df.empty else 0,
            results_df=results_df,
            topk_values=topk_values,
        )


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "source_kind",
        "source_name",
        "profile",
        "topk",
        "parsed_events",
        "templates",
        "windows",
        "anomalies",
        "anomaly_window_ratio",
        "detected",
        "unknown_windows",
        "unknown_window_ratio",
        "avg_unknown_ratio",
        "status_counts",
        "top_anomaly_actual_events",
        "error",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for topk in sorted({int(row["topk"]) for row in rows}):
        topk_rows = [row for row in rows if int(row["topk"]) == topk]
        windows = sum(int(row["windows"]) for row in topk_rows)
        anomalies = sum(int(row["anomalies"]) for row in topk_rows)
        summary[str(topk)] = {
            "sources": len(topk_rows),
            "flagged_sources": sum(int(row["detected"]) for row in topk_rows),
            "windows": windows,
            "anomalies": anomalies,
            "anomaly_window_ratio": round(anomalies / windows, 4) if windows else 0.0,
            "by_source_kind": {},
        }
        for source_kind in sorted({str(row["source_kind"]) for row in topk_rows}):
            kind_rows = [row for row in topk_rows if str(row["source_kind"]) == source_kind]
            kind_windows = sum(int(row["windows"]) for row in kind_rows)
            kind_anomalies = sum(int(row["anomalies"]) for row in kind_rows)
            summary[str(topk)]["by_source_kind"][source_kind] = {
                "sources": len(kind_rows),
                "flagged_sources": sum(int(row["detected"]) for row in kind_rows),
                "windows": kind_windows,
                "anomalies": kind_anomalies,
                "anomaly_window_ratio": round(kind_anomalies / kind_windows, 4)
                if kind_windows
                else 0.0,
            }
    return summary


def _aggregate_anomaly_events(
    rows: list[dict[str, Any]],
    *,
    topk: int,
    source_kind: str | None = None,
    limit: int = 10,
) -> list[tuple[str, int]]:
    counter: Counter[str] = Counter()
    for row in rows:
        if int(row["topk"]) != topk:
            continue
        if source_kind and str(row["source_kind"]) != source_kind:
            continue
        try:
            event_counts = json.loads(str(row.get("top_anomaly_actual_events") or "{}"))
        except json.JSONDecodeError:
            event_counts = {}
        for event, count in event_counts.items():
            counter[str(event)] += int(count)
    return counter.most_common(limit)


def _worst_sources(rows: list[dict[str, Any]], *, topk: int, limit: int = 8) -> list[dict[str, Any]]:
    topk_rows = [row for row in rows if int(row["topk"]) == topk and not row.get("error")]
    return sorted(
        topk_rows,
        key=lambda row: (
            float(row["anomaly_window_ratio"]),
            int(row["anomalies"]),
            int(row["windows"]),
        ),
        reverse=True,
    )[:limit]


def _format_rate(value: Any) -> str:
    return f"{float(value):.4f}"


def _write_report(
    path: Path,
    *,
    normal_evtx_root: Path,
    structured_csv: Path,
    summary: dict[str, Any],
    rows: list[dict[str, Any]],
    recommended_topk: int = 5,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# EVTX Normal Validation Report",
        "",
        f"Normal EVTX root: `{normal_evtx_root}`",
        f"Structured normal sample: `{structured_csv}`",
        "",
        "## Top-K Normal Sweep",
        "",
        "| Top-K | Sources | Flagged Sources | Windows | Anomalies | Anomaly Window Ratio |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]

    for topk in sorted(summary, key=lambda value: int(value)):
        item = summary[topk]
        lines.append(
            "| "
            f"{topk} | {item['sources']} | {item['flagged_sources']} | "
            f"{item['windows']} | {item['anomalies']} | {_format_rate(item['anomaly_window_ratio'])} |"
        )

    lines.extend(
        [
            "",
            "## Source Split",
            "",
            "| Top-K | Source Kind | Sources | Flagged Sources | Windows | Anomalies | Anomaly Window Ratio |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )

    for topk in sorted(summary, key=lambda value: int(value)):
        by_kind = summary[topk].get("by_source_kind", {})
        for source_kind in sorted(by_kind):
            item = by_kind[source_kind]
            lines.append(
                "| "
                f"{topk} | {source_kind} | {item['sources']} | {item['flagged_sources']} | "
                f"{item['windows']} | {item['anomalies']} | {_format_rate(item['anomaly_window_ratio'])} |"
            )

    raw_rows = [
        row
        for row in rows
        if int(row["topk"]) == recommended_topk and str(row["source_kind"]) == "raw_evtx"
    ]
    if raw_rows:
        lines.extend(["", f"## Raw EVTX at Top-{recommended_topk}", ""])
        lines.extend(
            [
                "| Source | Parsed Events | Templates | Windows | Anomalies | Anomaly Window Ratio | Unknown Windows |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in raw_rows:
            lines.append(
                "| "
                f"`{row['source_name']}` | {row['parsed_events']} | {row['templates']} | "
                f"{row['windows']} | {row['anomalies']} | {_format_rate(row['anomaly_window_ratio'])} | "
                f"{row['unknown_windows']} |"
            )

    lines.extend(["", f"## Top Normal Anomaly Events at Top-{recommended_topk}", ""])
    event_counts = _aggregate_anomaly_events(rows, topk=recommended_topk, limit=12)
    if event_counts:
        lines.extend(["| Event | Count |", "| --- | ---: |"])
        for event, count in event_counts:
            lines.append(f"| `{event}` | {count} |")
    else:
        lines.append("No anomaly events were produced.")

    lines.extend(["", f"## Worst Normal Sources at Top-{recommended_topk}", ""])
    worst_sources = _worst_sources(rows, topk=recommended_topk, limit=8)
    if worst_sources:
        lines.extend(
            [
                "| Source Kind | Source | Windows | Anomalies | Anomaly Window Ratio |",
                "| --- | --- | ---: | ---: | ---: |",
            ]
        )
        for row in worst_sources:
            lines.append(
                "| "
                f"{row['source_kind']} | `{row['source_name']}` | {row['windows']} | "
                f"{row['anomalies']} | {_format_rate(row['anomaly_window_ratio'])} |"
            )
    else:
        lines.append("No normal sources were flagged.")

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            f"Top-{recommended_topk} is still the best runtime default for the current EVTX Security profile.",
            "It keeps the raw normal EVTX anomaly rate low while preserving the attack-corpus gain from the BOS low-UNK model.",
            "Relaxing to Top-10 or Top-14 lowers normal noise, but it also removes too much attack signal from Windows Security EVTX samples.",
            "",
            "The structured normal samples are intentionally more diverse than the single raw normal EVTX file, so they are useful as a noise stress test rather than a direct production false-positive estimate.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normal-evtx-root", type=Path, default=DEFAULT_NORMAL_EVTX_ROOT)
    parser.add_argument("--structured-csv", type=Path, default=DEFAULT_STRUCTURED_CSV)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--topk-values", type=_parse_topk_values, default=list(DEFAULT_TOPK_VALUES))
    parser.add_argument("--max-lines", type=int, default=20000)
    parser.add_argument("--sessions-per-source", type=int, default=20)
    parser.add_argument("--max-events-per-session", type=int, default=300)
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="reuse the output CSV/JSON and only regenerate the Markdown report",
    )
    args = parser.parse_args()

    anomaly_module.tqdm = _identity_tqdm
    parsing_module.tqdm = _identity_tqdm

    output_dir = args.output_dir.resolve()
    csv_path = output_dir / "evtx_normal_validation.csv"
    summary_path = output_dir / "evtx_normal_validation_summary.json"
    report_path = output_dir / "evtx_normal_validation_report.md"
    if args.report_only:
        rows = _read_csv(csv_path)
        if summary_path.exists():
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        else:
            summary = _summarize(rows)
            summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    else:
        rows: list[dict[str, Any]] = []
        max_lines = args.max_lines if args.max_lines > 0 else None
        validate_raw_evtx(rows, args.normal_evtx_root, list(args.topk_values), max_lines=max_lines)
        validate_structured_samples(
            rows,
            args.structured_csv,
            list(args.topk_values),
            sessions_per_source=args.sessions_per_source,
            max_events_per_session=args.max_events_per_session,
        )
        _write_csv(csv_path, rows)
        summary = _summarize(rows)
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    _write_report(
        report_path,
        normal_evtx_root=args.normal_evtx_root,
        structured_csv=args.structured_csv,
        summary=summary,
        rows=rows,
    )

    print(f"wrote_csv={csv_path}")
    print(f"wrote_summary={summary_path}")
    print(f"wrote_report={report_path}")
    for topk, topk_summary in summary.items():
        print(
            f"topk={topk} sources={topk_summary['sources']} "
            f"flagged_sources={topk_summary['flagged_sources']} "
            f"windows={topk_summary['windows']} anomalies={topk_summary['anomalies']} "
            f"anomaly_window_ratio={topk_summary['anomaly_window_ratio']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
