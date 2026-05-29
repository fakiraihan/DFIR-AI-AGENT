"""Build DeepLog-ready Linux cross-dataset CSVs from Loghub and organization-x.

The Loghub Linux sample is unlabelled and is used as normal-only training data.
The organization-x dataset carries YAML pattern rules; this builder applies
those rules to raw lines and emits a labelled structured CSV for evaluation.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib.parse import unquote_plus

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.linux_log_templates import (  # noqa: E402
    build_linux_event_template,
    classify_linux_log_source,
    parse_linux_timestamp,
)


DEFAULT_LOGHUB_INPUT = Path(r"D:\FAKI\DATASETLINUX\LOGHUB\Linux_2k.log")
DEFAULT_ORGANIZATIONX_INPUT = Path(r"D:\FAKI\DATASETLINUX\ADF LINUX\organization-x")
DEFAULT_LOGHUB_OUTPUT = Path(r"D:\FAKI\NEWMLMODL\dataset\linux_loghub")
DEFAULT_ORGANIZATIONX_OUTPUT = Path(r"D:\FAKI\NEWMLMODL\dataset\linux_organizationx")
DEFAULT_LOGHUB_NAME = "linux_loghub.log"
DEFAULT_ORGANIZATIONX_NAME = "linux_organizationx.log"
SUPPORTED_ORGANIZATIONX_SOURCES = ("auth", "syslog", "apache")

APACHE_ACCESS_PATTERN = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+\[(?P<stamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>.*?)\s+(?P<protocol>HTTP/[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
)
APACHE_ERROR_PATTERN = re.compile(
    r"^\[(?P<stamp>[^\]]+)\]\s+\[(?P<level>[^\]:]+)"
    r"(?::[^\]]+)?\]\s+(?P<message>.*)$"
)


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


def _open_text(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def _normal_label_counts(frame: pd.DataFrame) -> dict[str, int]:
    return {
        str(key): int(value)
        for key, value in frame["Label"].value_counts().to_dict().items()
    }


def _finalize_rows(
    rows: list[dict[str, Any]],
    *,
    output_dir: Path,
    log_name: str,
    summary_path: Path,
    summary_extra: dict[str, Any],
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    structured_path = output_dir / f"{log_name}_structured.csv"
    log_path = output_dir / log_name

    if rows:
        final = pd.DataFrame(rows)
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
        **summary_extra,
        "output_dir": output_dir,
        "structured_path": structured_path,
        "log_path": log_path,
        "log_name": log_name,
        "rows": int(len(final)),
        "templates": int(final["EventTemplate"].nunique()) if not final.empty else 0,
        "label_counts": _normal_label_counts(final) if not final.empty else {},
        "log_source_counts": (
            final["LogSource"].value_counts().to_dict() if not final.empty else {}
        ),
        "top_event_templates": (
            final["EventTemplate"].value_counts().head(30).to_dict() if not final.empty else {}
        ),
    }
    _write_json(summary_path, summary)
    return summary


def build_linux_loghub_dataset(
    *,
    input_log: Path,
    output_dir: Path,
    log_name: str = DEFAULT_LOGHUB_NAME,
    max_lines: int | None = None,
    agent_name: str = "loghub_linux",
    summary_path: Path | None = None,
) -> dict[str, Any]:
    """Build a normal-only structured CSV from Loghub's Linux_2k.log sample."""
    input_log = Path(input_log)
    output_dir = Path(output_dir)
    if not input_log.exists():
        raise FileNotFoundError(f"Loghub Linux input not found: {input_log}")

    rows: list[dict[str, Any]] = []
    with input_log.open("r", encoding="utf-8", errors="ignore") as file_obj:
        for line_number, line in enumerate(file_obj, start=1):
            if max_lines is not None and line_number > max_lines:
                break
            raw_line = line.rstrip("\r\n").lstrip("\ufeff")
            if not raw_line.strip():
                continue
            source = classify_linux_log_source(raw_line=raw_line) or "syslog"
            rows.append(
                {
                    "LineId": len(rows) + 1,
                    "Timestamp": len(rows) + 1,
                    "Label": "-",
                    "EventTemplate": build_linux_event_template(raw_line, source_hint=source),
                    "Content": raw_line,
                    "AgentName": agent_name,
                    "SourceDataset": "loghub_linux",
                    "LogSource": source,
                    "SourceFile": input_log.name,
                    "OriginalLineNumber": line_number,
                    "AttackLabels": "",
                }
            )

    return _finalize_rows(
        rows,
        output_dir=output_dir,
        log_name=log_name,
        summary_path=summary_path or output_dir / "linux_loghub_summary.json",
        summary_extra={"input_log": input_log, "agent_name": agent_name},
    )


def _parse_organizationx_rules(rules_path: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_filter = False
    for raw_line in rules_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("- id:"):
            if current:
                rules.append(current)
            current = {"id": _yaml_scalar(stripped.split(":", 1)[1]), "label": None, "filter": []}
            in_filter = False
        elif current and stripped.startswith("ground_truth_label:"):
            current["label"] = _yaml_scalar(stripped.split(":", 1)[1])
        elif current and stripped.startswith("filter:"):
            in_filter = True
        elif current and in_filter and stripped.startswith("- "):
            current["filter"].append(_yaml_scalar(stripped[2:]))
    if current:
        rules.append(current)
    return [rule for rule in rules if rule.get("filter")]


def _yaml_scalar(value: str) -> str:
    return value.strip().strip("\"'")


def _match_rule_filter(raw_line: str, pattern: str) -> bool:
    needle = _yaml_scalar(pattern).replace("%", "").lower()
    return bool(needle) and needle in raw_line.lower()


def _attack_labels_for_line(raw_line: str, rules: Iterable[dict[str, Any]]) -> list[str]:
    labels: set[str] = set()
    for rule in rules:
        filters = [str(item) for item in rule.get("filter", [])]
        if filters and all(_match_rule_filter(raw_line, item) for item in filters):
            labels.add(str(rule.get("label") or rule.get("id") or "attack"))
    return sorted(labels)


def _classify_organizationx_path(relative_path: Path) -> str | None:
    posix = relative_path.as_posix().lower()
    name = relative_path.name.lower()
    if name.startswith("auth.log"):
        return "auth"
    if name.startswith("syslog"):
        return "syslog"
    if posix.startswith("apache2/"):
        return "apache"
    return None


def _iter_organizationx_files(
    log_root: Path,
    include_sources: set[str],
) -> Iterator[tuple[Path, Path, str]]:
    for path in sorted(log_root.rglob("*")):
        if not path.is_file():
            continue
        relative_path = path.relative_to(log_root)
        source = _classify_organizationx_path(relative_path)
        if source and source in include_sources:
            yield path, relative_path, source


def _parse_sources(value: str | Iterable[str]) -> set[str]:
    parts = value.split(",") if isinstance(value, str) else list(value)
    sources = {str(part).strip().lower() for part in parts if str(part).strip()}
    invalid = sources - set(SUPPORTED_ORGANIZATIONX_SOURCES)
    if invalid:
        raise ValueError(f"Unsupported organization-x sources: {sorted(invalid)}")
    return sources or set(SUPPORTED_ORGANIZATIONX_SOURCES)


def _parse_apache_timestamp(raw_line: str) -> int:
    access_match = APACHE_ACCESS_PATTERN.match(raw_line)
    if access_match:
        try:
            parsed = datetime.strptime(access_match.group("stamp"), "%d/%b/%Y:%H:%M:%S %z")
            return int(parsed.timestamp())
        except ValueError:
            return 0

    error_match = APACHE_ERROR_PATTERN.match(raw_line)
    if error_match:
        for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
            try:
                parsed = datetime.strptime(error_match.group("stamp"), fmt)
                return int(parsed.replace(tzinfo=timezone.utc).timestamp())
            except ValueError:
                continue
    return 0


def _generic_action(message: str) -> str:
    text = unquote_plus(message.lower())
    if any(token in text for token in ("union", "select", "sleep", "concat")):
        return "sql_probe"
    if any(token in text for token in ("etc/passwd", "../", "..%2f")):
        return "file_probe"
    if any(token in text for token in ("<script", "alert(", "document.")):
        return "xss_probe"
    if any(token in text for token in ("cmd=", "command=", "<?php", "base64")):
        return "remote_code_probe"
    if "login" in text:
        return "login"
    if "cgi-bin" in text:
        return "cgi"
    return "request"


def _build_apache_template(raw_line: str) -> str:
    access_match = APACHE_ACCESS_PATTERN.match(raw_line)
    if access_match:
        method = access_match.group("method").upper()
        status = access_match.group("status")
        action = _generic_action(access_match.group("path"))
        return f"ApacheAccess method={method} status={status} action={action}"

    error_match = APACHE_ERROR_PATTERN.match(raw_line)
    if error_match:
        level = error_match.group("level").strip().lower() or "unknown"
        action = _generic_action(error_match.group("message"))
        return f"ApacheError level={level} action={action}"

    return f"ApacheLog action={_generic_action(raw_line)}"


def _event_template_for_organizationx(raw_line: str, source: str) -> str:
    if source == "apache":
        return _build_apache_template(raw_line)
    return build_linux_event_template(raw_line, source_hint=source)


def _timestamp_for_organizationx(raw_line: str, source: str, default_year: int) -> int:
    if source == "apache":
        return _parse_apache_timestamp(raw_line)
    return parse_linux_timestamp(raw_line, default_year=default_year)


def build_organizationx_dataset(
    *,
    input_root: Path,
    output_dir: Path,
    log_name: str = DEFAULT_ORGANIZATIONX_NAME,
    include_sources: str | Iterable[str] = SUPPORTED_ORGANIZATIONX_SOURCES,
    max_lines_per_file: int | None = None,
    default_year: int = 2025,
    summary_path: Path | None = None,
) -> dict[str, Any]:
    """Build a labelled structured CSV from the organization-x dataset."""
    input_root = Path(input_root)
    output_dir = Path(output_dir)
    log_root = input_root / "log"
    rules_path = input_root / "ground-truth" / "organization-x.yaml"
    if not log_root.exists():
        raise FileNotFoundError(f"organization-x log root not found: {log_root}")
    if not rules_path.exists():
        raise FileNotFoundError(f"organization-x ground truth rules not found: {rules_path}")

    include_source_set = _parse_sources(include_sources)
    rules = _parse_organizationx_rules(rules_path)
    rows: list[dict[str, Any]] = []
    source_counts: Counter[str] = Counter()
    attack_label_counts: Counter[str] = Counter()

    for log_path, relative_path, source in _iter_organizationx_files(log_root, include_source_set):
        source_name = relative_path.as_posix()
        with _open_text(log_path) as file_obj:
            for line_number, line in enumerate(file_obj, start=1):
                if max_lines_per_file is not None and line_number > max_lines_per_file:
                    break
                raw_line = line.rstrip("\r\n").lstrip("\ufeff")
                if not raw_line.strip():
                    continue

                attack_labels = _attack_labels_for_line(raw_line, rules)
                attack_label_counts.update(attack_labels)
                timestamp = _timestamp_for_organizationx(raw_line, source, default_year)
                rows.append(
                    {
                        "LineId": len(rows) + 1,
                        "Timestamp": timestamp if timestamp > 0 else len(rows) + 1,
                        "Label": "attack" if attack_labels else "-",
                        "EventTemplate": _event_template_for_organizationx(raw_line, source),
                        "Content": raw_line,
                        "AgentName": f"organization_x_{source}",
                        "SourceDataset": "organization_x",
                        "LogSource": source,
                        "SourceFile": source_name,
                        "OriginalLineNumber": line_number,
                        "AttackLabels": "|".join(attack_labels),
                    }
                )
                source_counts[source_name] += 1

    rows.sort(
        key=lambda row: (
            str(row["AgentName"]),
            int(row["Timestamp"]),
            str(row["SourceFile"]),
            int(row["OriginalLineNumber"]),
        )
    )

    return _finalize_rows(
        rows,
        output_dir=output_dir,
        log_name=log_name,
        summary_path=summary_path or output_dir / "linux_organizationx_summary.json",
        summary_extra={
            "input_root": input_root,
            "log_root": log_root,
            "rules_path": rules_path,
            "include_sources": sorted(include_source_set),
            "rules": len(rules),
            "sources": dict(source_counts.most_common()),
            "attack_label_counts": dict(attack_label_counts.most_common()),
        },
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("loghub", "organizationx"), required=True)
    parser.add_argument("--input", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--log-name", default=None)
    parser.add_argument("--include-sources", default=",".join(SUPPORTED_ORGANIZATIONX_SOURCES))
    parser.add_argument("--max-lines", type=int, default=None)
    parser.add_argument("--default-year", type=int, default=2025)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.mode == "loghub":
        summary = build_linux_loghub_dataset(
            input_log=args.input or DEFAULT_LOGHUB_INPUT,
            output_dir=args.output_dir or DEFAULT_LOGHUB_OUTPUT,
            log_name=args.log_name or DEFAULT_LOGHUB_NAME,
            max_lines=args.max_lines,
        )
    else:
        summary = build_organizationx_dataset(
            input_root=args.input or DEFAULT_ORGANIZATIONX_INPUT,
            output_dir=args.output_dir or DEFAULT_ORGANIZATIONX_OUTPUT,
            log_name=args.log_name or DEFAULT_ORGANIZATIONX_NAME,
            include_sources=args.include_sources,
            max_lines_per_file=args.max_lines,
            default_year=args.default_year,
        )

    print(json.dumps(summary, indent=2, sort_keys=True, default=_json_default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
