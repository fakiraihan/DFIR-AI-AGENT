"""Build a DeepLog-ready Linux AIT-LDS/Kyoushi structured dataset.

The converter focuses on Linux DFIR sources first: auth.log, audit.log, and
syslog. It reads AIT-LDS/Kyoushi's mirrored `gather` and `labels` layout and
writes the same structured CSV contract used by the existing DeepLog tooling.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.linux_log_templates import (  # noqa: E402
    build_linux_event_template,
    classify_linux_log_path,
    parse_linux_timestamp,
)


DEFAULT_INPUT = Path(r"D:\FAKI\NEWMLMODL\dataset\ait_lds")
DEFAULT_OUTPUT = Path(r"D:\FAKI\NEWMLMODL\dataset\linux_ait_lds")
DEFAULT_LOG_NAME = "linux_ait_lds.log"
DEFAULT_STREAMS = ("auth", "audit", "syslog")


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    try:
        import numpy as np

        if isinstance(value, (np.integer,)):
            return int(value)
        if isinstance(value, (np.floating,)):
            return float(value)
    except Exception:
        pass
    return str(value)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=_json_default),
        encoding="utf-8",
    )


def _resolve_dataset_roots(input_root: Path) -> tuple[Path, Path]:
    if (input_root / "gather").exists():
        return input_root / "gather", input_root / "labels"
    if input_root.name.lower() == "gather":
        return input_root, input_root.parent / "labels"
    return input_root, input_root.parent / "labels"


def _host_from_relative_path(relative_path: Path) -> str:
    parts = relative_path.parts
    if parts:
        return parts[0]
    return "linux_host"


def _load_label_lines(labels_path: Path) -> dict[int, list[str]]:
    if not labels_path.exists():
        return {}

    labels_by_line: dict[int, set[str]] = {}
    with labels_path.open("r", encoding="utf-8", errors="ignore") as file_obj:
        for raw_line in file_obj:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                item = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            try:
                line_number = int(item.get("line"))
            except (TypeError, ValueError):
                continue
            raw_labels = item.get("labels") or []
            if isinstance(raw_labels, str):
                raw_labels = [raw_labels]
            label_set = labels_by_line.setdefault(line_number, set())
            for label in raw_labels:
                label_text = str(label).strip()
                if label_text:
                    label_set.add(label_text)

    return {line: sorted(labels) for line, labels in labels_by_line.items()}


def _iter_target_log_files(
    gather_root: Path,
    include_streams: set[str],
) -> Iterable[tuple[Path, Path, str]]:
    for log_path in sorted(gather_root.rglob("*")):
        if not log_path.is_file():
            continue
        relative_path = log_path.relative_to(gather_root)
        if "logs" not in {part.lower() for part in relative_path.parts}:
            continue
        source = classify_linux_log_path(log_path)
        if source is None or source not in include_streams:
            continue
        yield log_path, relative_path, source


def _parse_streams(value: str | Iterable[str]) -> set[str]:
    if isinstance(value, str):
        parts = value.split(",")
    else:
        parts = list(value)
    streams = {str(part).strip().lower() for part in parts if str(part).strip()}
    invalid = streams - set(DEFAULT_STREAMS)
    if invalid:
        raise ValueError(f"Unsupported Linux AIT-LDS streams: {sorted(invalid)}")
    return streams or set(DEFAULT_STREAMS)


def build_linux_ait_lds_dataset(
    *,
    input_root: Path,
    output_dir: Path,
    log_name: str = DEFAULT_LOG_NAME,
    include_streams: str | Iterable[str] = DEFAULT_STREAMS,
    max_lines_per_file: int | None = None,
    default_year: int = 2022,
    summary_path: Path | None = None,
) -> dict[str, Any]:
    """Build `linux_ait_lds.log_structured.csv` and return a compact summary."""
    input_root = Path(input_root)
    output_dir = Path(output_dir)
    gather_root, labels_root = _resolve_dataset_roots(input_root)
    if not gather_root.exists():
        raise FileNotFoundError(f"AIT-LDS gather root not found: {gather_root}")

    include_stream_set = _parse_streams(include_streams)
    rows: list[dict[str, Any]] = []
    source_counts: Counter[str] = Counter()

    for log_path, relative_path, source in _iter_target_log_files(gather_root, include_stream_set):
        labels_by_line = _load_label_lines(labels_root / relative_path)
        host_name = _host_from_relative_path(relative_path)
        source_name = str(relative_path).replace("\\", "/")

        with log_path.open("r", encoding="utf-8", errors="ignore") as file_obj:
            for line_number, line in enumerate(file_obj, start=1):
                if max_lines_per_file is not None and line_number > max_lines_per_file:
                    break

                raw_line = line.rstrip("\r\n").lstrip("\ufeff")
                if not raw_line.strip():
                    continue

                attack_labels = labels_by_line.get(line_number, [])
                event_template = build_linux_event_template(raw_line, source_hint=source)
                rows.append(
                    {
                        "LineId": len(rows) + 1,
                        "Timestamp": parse_linux_timestamp(raw_line, default_year=default_year),
                        "Label": "attack" if attack_labels else "-",
                        "EventTemplate": event_template,
                        "Content": raw_line,
                        "AgentName": host_name,
                        "SourceDataset": "ait_lds",
                        "LogSource": source,
                        "SourceFile": source_name,
                        "OriginalLineNumber": line_number,
                        "AttackLabels": "|".join(attack_labels),
                    }
                )
                source_counts[source_name] += 1

    output_dir.mkdir(parents=True, exist_ok=True)
    structured_path = output_dir / f"{log_name}_structured.csv"
    log_path = output_dir / log_name

    if rows:
        final = pd.DataFrame(rows)
        final = final.sort_values(
            ["AgentName", "Timestamp", "SourceFile", "OriginalLineNumber"],
            kind="stable",
        ).reset_index(drop=True)
        final["LineId"] = range(1, len(final) + 1)
        final["EventId"] = pd.factorize(final["EventTemplate"])[0] + 1
        final = final[
            [
                "LineId",
                "Timestamp",
                "Label",
                "EventId",
                "EventTemplate",
                "Content",
                "AgentName",
                "SourceDataset",
                "LogSource",
                "SourceFile",
                "OriginalLineNumber",
                "AttackLabels",
            ]
        ]
    else:
        final = pd.DataFrame(
            columns=[
                "LineId",
                "Timestamp",
                "Label",
                "EventId",
                "EventTemplate",
                "Content",
                "AgentName",
                "SourceDataset",
                "LogSource",
                "SourceFile",
                "OriginalLineNumber",
                "AttackLabels",
            ]
        )

    final.to_csv(structured_path, index=False)
    log_path.write_text("\n".join(final["Content"].astype(str).tolist()), encoding="utf-8")

    summary = {
        "input_root": input_root,
        "gather_root": gather_root,
        "labels_root": labels_root,
        "output_dir": output_dir,
        "structured_path": structured_path,
        "log_path": log_path,
        "log_name": log_name,
        "include_streams": sorted(include_stream_set),
        "default_year": default_year,
        "rows": int(len(final)),
        "templates": int(final["EventTemplate"].nunique()) if not final.empty else 0,
        "label_counts": final["Label"].value_counts().to_dict() if not final.empty else {},
        "log_source_counts": final["LogSource"].value_counts().to_dict() if not final.empty else {},
        "sources": dict(source_counts.most_common()),
        "top_event_templates": (
            final["EventTemplate"].value_counts().head(30).to_dict() if not final.empty else {}
        ),
    }
    _write_json(summary_path or output_dir / "linux_ait_lds_summary.json", summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--log-name", default=DEFAULT_LOG_NAME)
    parser.add_argument("--include-streams", default=",".join(DEFAULT_STREAMS))
    parser.add_argument("--max-lines-per-file", type=int, default=None)
    parser.add_argument("--default-year", type=int, default=2022)
    parser.add_argument("--summary", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = build_linux_ait_lds_dataset(
        input_root=args.input_root,
        output_dir=args.output_dir,
        log_name=args.log_name,
        include_streams=args.include_streams,
        max_lines_per_file=args.max_lines_per_file,
        default_year=args.default_year,
        summary_path=args.summary,
    )
    print(json.dumps(summary, indent=2, sort_keys=True, default=_json_default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
