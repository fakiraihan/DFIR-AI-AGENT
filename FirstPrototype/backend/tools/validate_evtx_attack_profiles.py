"""Validate DeepLog EVTX profiles against labelled attack sample files.

Every EVTX file under the attack-sample root is treated as an attack-positive
sample. The goal is not to prove exact attack semantics per event, but to
measure whether the current parser/profile/model combination surfaces at least
one DeepLog anomaly per file and which sections are still blind spots.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from config import settings  # noqa: E402
import modules.anomaly as anomaly_module  # noqa: E402
import modules.parsing as parsing_module  # noqa: E402
from modules.anomaly import DeepLogDetector  # noqa: E402
from services.parsing_service import parse_with_profile  # noqa: E402


DEFAULT_ROOT = Path(r"D:\FAKI\LogADEmpirical-dev\EVTX-ATTACK-SAMPLES")
DEFAULT_OUTPUT_DIR = BACKEND_DIR / "data" / "evtx_attack_validation"
DEFAULT_TOPK_VALUES = (5, 10, 14)


def _identity_tqdm(iterable: Iterable[Any], *args: Any, **kwargs: Any) -> Iterable[Any]:
    return iterable


def _parse_topk_values(value: str) -> list[int]:
    values = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        parsed = int(part)
        if parsed <= 0:
            raise argparse.ArgumentTypeError("topk values must be positive integers")
        values.append(parsed)
    if not values:
        raise argparse.ArgumentTypeError("at least one topk value is required")
    return sorted(set(values))


def _section_for(path: Path, root: Path) -> str:
    relative = path.relative_to(root)
    return relative.parts[0] if len(relative.parts) > 1 else "(root)"


def _subsection_for(path: Path, root: Path) -> str:
    relative = path.relative_to(root)
    if len(relative.parts) <= 2:
        return ""
    return "/".join(relative.parts[1:-1])


def _iter_evtx_files(root: Path, sections: set[str], limit: int) -> list[Path]:
    paths = []
    for path in sorted(root.rglob("*.evtx")):
        relative_parts = path.relative_to(root).parts
        if any(part.startswith(".") for part in relative_parts):
            continue
        section = _section_for(path, root)
        if sections and section not in sections:
            continue
        paths.append(path)
        if limit > 0 and len(paths) >= limit:
            break
    return paths


def _status_counts(results_df: Any) -> dict[str, int]:
    if results_df.empty or "evaluation_status" not in results_df.columns:
        return {}
    return {
        str(key): int(value)
        for key, value in results_df["evaluation_status"].value_counts().to_dict().items()
    }


def _actual_event_counts_for_mask(results_df: Any, anomaly_mask: list[bool]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    if results_df.empty or "actual_event" not in results_df.columns:
        return {}
    for is_anomaly, value in zip(anomaly_mask, results_df["actual_event"].astype(str).tolist()):
        if is_anomaly:
            counter[value] += 1
    return dict(counter.most_common(8))


def _avg_unknown_ratio(results_df: Any) -> float:
    if results_df.empty or "unknown_ratio" not in results_df.columns:
        return 0.0
    return round(float(results_df["unknown_ratio"].mean()), 4)


def _unknown_window_count(results_df: Any, status_counts: dict[str, int]) -> int:
    if not results_df.empty and "unknown_count" in results_df.columns:
        return int((results_df["unknown_count"] > 0).sum())
    return sum(
        status_counts.get(status, 0)
        for status in ("unknown_template", "unknown_template_ratio_exceeded")
    )


def _detector_cache_key(
    profile: dict[str, Any],
    topk: int,
) -> tuple[str, str, int, int, bool, str, int]:
    return (
        str(profile["model_path"]),
        str(profile["vocab_path"]),
        int(profile["window_size"]),
        int(topk),
        bool(profile.get("use_bos_context", False)),
        str(profile.get("bos_token", "<BOS>")),
        int(profile.get("bos_count") or 0),
    )


def _parse_topk_indices(value: Any) -> list[int]:
    indices: list[int] = []
    for part in str(value or "").split("|"):
        part = part.strip()
        if not part:
            continue
        try:
            indices.append(int(part))
        except ValueError:
            continue
    return indices


def _topk_projection(results_df: Any, topk: int) -> tuple[list[bool], dict[str, int]]:
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


def _get_detector(
    cache: dict[tuple[str, str, int, int, bool, str, int], DeepLogDetector],
    profile: dict[str, Any],
    topk: int,
) -> DeepLogDetector:
    key = _detector_cache_key(profile, topk)
    detector = cache.get(key)
    if detector is not None:
        return detector

    detector = DeepLogDetector(
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
    cache[key] = detector
    return detector


def _validate_file(
    path: Path,
    root: Path,
    topk_values: list[int],
    max_lines: int | None,
    detector_cache: dict[tuple[str, str, int, int, bool, str, int], DeepLogDetector],
) -> list[dict[str, Any]]:
    section = _section_for(path, root)
    subsection = _subsection_for(path, root)
    parsed_df, templates, profile = parse_with_profile(
        str(path),
        settings,
        max_lines=max_lines,
    )

    rows = []
    max_topk = max(topk_values)
    detector = _get_detector(detector_cache, profile, max_topk)
    results_df = detector.detect_anomalies(parsed_df)
    unknown_windows = _unknown_window_count(results_df, _status_counts(results_df))
    windows = len(results_df)
    avg_unknown_ratio = _avg_unknown_ratio(results_df)
    for topk in topk_values:
        anomaly_mask, status_counts = _topk_projection(results_df, topk)
        anomalies = sum(1 for is_anomaly in anomaly_mask if is_anomaly)
        rows.append(
            {
                "section": section,
                "subsection": subsection,
                "file_name": path.name,
                "relative_path": str(path.relative_to(root)),
                "path": str(path),
                "size_bytes": path.stat().st_size,
                "profile": profile["name"],
                "template_strategy": profile["template_strategy"],
                "model_path": str(profile["model_path"]),
                "vocab_path": str(profile["vocab_path"]),
                "window_size": profile["window_size"],
                "topk": topk,
                "parsed_events": len(parsed_df),
                "templates": len(templates),
                "windows": windows,
                "anomalies": anomalies,
                "detected": int(anomalies > 0),
                "sequence_anomalies": status_counts.get("deeplog_topk_miss", 0),
                "unknown_windows": unknown_windows,
                "unknown_window_ratio": round(unknown_windows / windows, 4)
                if windows
                else 0.0,
                "avg_unknown_ratio": avg_unknown_ratio,
                "anomaly_window_ratio": round(anomalies / windows, 4)
                if windows
                else 0.0,
                "status_counts": json.dumps(status_counts, sort_keys=True),
                "top_anomaly_actual_events": json.dumps(
                    _actual_event_counts_for_mask(results_df, anomaly_mask),
                    sort_keys=True,
                ),
                "error": "",
            }
        )
    return rows


def _error_rows(
    path: Path,
    root: Path,
    topk_values: list[int],
    error: Exception,
) -> list[dict[str, Any]]:
    return [
        {
            "section": _section_for(path, root),
            "subsection": _subsection_for(path, root),
            "file_name": path.name,
            "relative_path": str(path.relative_to(root)),
            "path": str(path),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "profile": "error",
            "template_strategy": "",
            "model_path": "",
            "vocab_path": "",
            "window_size": 0,
            "topk": topk,
            "parsed_events": 0,
            "templates": 0,
            "windows": 0,
            "anomalies": 0,
            "detected": 0,
            "sequence_anomalies": 0,
            "unknown_windows": 0,
            "unknown_window_ratio": 0.0,
            "avg_unknown_ratio": 0.0,
            "anomaly_window_ratio": 0.0,
            "status_counts": "{}",
            "top_anomaly_actual_events": "{}",
            "error": str(error),
        }
        for topk in topk_values
    ]


def _int_value(row: dict[str, Any], field: str) -> int:
    return int(row.get(field) or 0)


def _float_value(row: dict[str, Any], field: str) -> float:
    return float(row.get(field) or 0.0)


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_topk: dict[int, dict[str, Any]] = {}
    by_topk_section: dict[int, dict[str, dict[str, Any]]] = defaultdict(dict)

    topk_values = sorted({_int_value(row, "topk") for row in rows})
    for topk in topk_values:
        topk_rows = [row for row in rows if _int_value(row, "topk") == topk]
        files = len(topk_rows)
        detected = sum(_int_value(row, "detected") for row in topk_rows)
        missed_rows = [row for row in topk_rows if _int_value(row, "detected") == 0]
        total_windows = sum(_int_value(row, "windows") for row in topk_rows)
        total_anomalies = sum(_int_value(row, "anomalies") for row in topk_rows)
        by_topk[topk] = {
            "files": files,
            "detected_files": detected,
            "missed_files": files - detected,
            "sample_recall": round(detected / files, 4) if files else 0.0,
            "total_windows": total_windows,
            "total_anomalies": total_anomalies,
            "anomaly_window_ratio": round(total_anomalies / total_windows, 4)
            if total_windows
            else 0.0,
            "avg_unknown_ratio_mean": round(
                sum(_float_value(row, "avg_unknown_ratio") for row in topk_rows) / files,
                4,
            )
            if files
            else 0.0,
            "missed_sections": dict(
                Counter(str(row["section"]) for row in missed_rows).most_common()
            ),
        }

        for section in sorted({str(row["section"]) for row in topk_rows}):
            section_rows = [row for row in topk_rows if str(row["section"]) == section]
            section_files = len(section_rows)
            section_detected = sum(_int_value(row, "detected") for row in section_rows)
            by_topk_section[topk][section] = {
                "files": section_files,
                "detected_files": section_detected,
                "missed_files": section_files - section_detected,
                "sample_recall": round(section_detected / section_files, 4)
                if section_files
                else 0.0,
                "total_anomalies": sum(
                    _int_value(row, "anomalies") for row in section_rows
                ),
                "profiles": dict(
                    Counter(str(row["profile"]) for row in section_rows).most_common()
                ),
            }

    return {
        "by_topk": by_topk,
        "by_topk_section": by_topk_section,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "section",
        "subsection",
        "file_name",
        "relative_path",
        "path",
        "size_bytes",
        "profile",
        "template_strategy",
        "model_path",
        "vocab_path",
        "window_size",
        "topk",
        "parsed_events",
        "templates",
        "windows",
        "anomalies",
        "detected",
        "sequence_anomalies",
        "unknown_windows",
        "unknown_window_ratio",
        "avg_unknown_ratio",
        "anomaly_window_ratio",
        "status_counts",
        "top_anomaly_actual_events",
        "error",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_missed_csv(path: Path, rows: list[dict[str, Any]], topk: int) -> None:
    missed_rows = [
        row
        for row in rows
        if _int_value(row, "topk") == topk and _int_value(row, "detected") == 0
    ]
    _write_csv(path, missed_rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--topk-values",
        type=_parse_topk_values,
        default=list(DEFAULT_TOPK_VALUES),
        help="Comma-separated inference topk values, for example: 5,10,14",
    )
    parser.add_argument("--max-lines", type=int, default=20000)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument(
        "--sections",
        default="",
        help="Comma-separated top-level sections to include.",
    )
    parser.add_argument(
        "--runtime-topk",
        type=int,
        default=10,
        help="Topk used for missed.csv extraction.",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    output_dir = args.output_dir.resolve()
    sections = {part.strip() for part in args.sections.split(",") if part.strip()}
    max_lines = args.max_lines if args.max_lines > 0 else None
    topk_values = list(args.topk_values)

    anomaly_module.tqdm = _identity_tqdm
    parsing_module.tqdm = _identity_tqdm

    paths = _iter_evtx_files(root, sections, args.limit)
    rows: list[dict[str, Any]] = []
    detector_cache: dict[tuple[str, str, int, int, bool, str, int], DeepLogDetector] = {}

    for index, path in enumerate(paths, start=1):
        print(f"[{index}/{len(paths)}] {path}", flush=True)
        try:
            rows.extend(
                _validate_file(path, root, topk_values, max_lines, detector_cache)
            )
        except Exception as exc:
            rows.extend(_error_rows(path, root, topk_values, exc))

    csv_path = output_dir / "evtx_attack_validation.csv"
    missed_path = output_dir / f"missed_topk{args.runtime_topk}.csv"
    summary_path = output_dir / "evtx_attack_validation_summary.json"

    _write_csv(csv_path, rows)
    _write_missed_csv(missed_path, rows, args.runtime_topk)
    summary = _summarize(rows)
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(f"wrote_csv={csv_path}")
    print(f"wrote_summary={summary_path}")
    print(f"wrote_missed={missed_path}")
    for topk, topk_summary in summary["by_topk"].items():
        print(
            "topk={topk} files={files} detected={detected_files} "
            "missed={missed_files} sample_recall={sample_recall} "
            "anomaly_window_ratio={anomaly_window_ratio}".format(
                topk=topk,
                **topk_summary,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
