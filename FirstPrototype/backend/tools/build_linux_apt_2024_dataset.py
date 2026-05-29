"""Build a DeepLog-ready dataset from Linux-APT-Dataset-2024.

The processed Mendeley workbook includes labels plus MITRE/TTP columns. This
converter intentionally builds templates from `full_log` only and keeps MITRE
columns out of the DeepLog input path to avoid label leakage.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote_plus
from zipfile import ZipFile

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.linux_log_templates import (  # noqa: E402
    build_linux_event_template,
    classify_linux_log_source,
)


DEFAULT_INPUT = Path(r"D:\FAKI\DATASETLINUX\Linux-APT-Dataset-2024\Processed Version.xlsx")
DEFAULT_OUTPUT = Path(r"D:\FAKI\NEWMLMODL\dataset\linux_apt_2024")
DEFAULT_LOG_NAME = "linux_apt_2024.log"

SPREADSHEET_NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
APACHE_ACCESS_PATTERN = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+\[(?P<stamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>.*?)\s+(?P<protocol>HTTP/[^"]+)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
)
ISO_TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
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


def _column_index(cell_ref: str) -> int:
    letters = ""
    for char in cell_ref:
        if char.isalpha():
            letters += char
        else:
            break
    value = 0
    for char in letters:
        value = value * 26 + ord(char.upper()) - 64
    return max(0, value - 1)


def _load_shared_strings(archive: ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    import xml.etree.ElementTree as ET

    shared: list[str] = []
    root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    for item in root.findall("a:si", SPREADSHEET_NS):
        shared.append("".join(text.text or "" for text in item.findall(".//a:t", SPREADSHEET_NS)))
    return shared


def _cell_value(cell: Any, shared_strings: list[str]) -> str:
    typ = cell.attrib.get("t")
    value_node = None
    for child in cell:
        if child.tag.endswith("}v"):
            value_node = child
            break
    if value_node is None or value_node.text is None:
        if typ == "inlineStr":
            return "".join(
                text.text or ""
                for text in cell.findall(".//a:t", SPREADSHEET_NS)
            )
        return ""

    raw_value = value_node.text
    if typ == "s" and raw_value:
        return shared_strings[int(raw_value)]
    return raw_value


def iter_xlsx_rows(xlsx_path: Path) -> Iterator[list[str]]:
    """Yield worksheet rows from the first sheet using only the standard library."""
    import xml.etree.ElementTree as ET

    with ZipFile(xlsx_path) as archive:
        shared_strings = _load_shared_strings(archive)
        sheet_path = "xl/worksheets/sheet1.xml"
        if sheet_path not in archive.namelist():
            raise FileNotFoundError(f"Expected first worksheet at {sheet_path}")

        with archive.open(sheet_path) as worksheet:
            for event, element in ET.iterparse(worksheet, events=("end",)):
                if not element.tag.endswith("}row"):
                    continue
                values: list[str] = []
                for cell in element:
                    if not cell.tag.endswith("}c"):
                        continue
                    index = _column_index(cell.attrib.get("r", "A1"))
                    while len(values) <= index:
                        values.append("")
                    values[index] = _cell_value(cell, shared_strings).strip()
                yield values
                element.clear()


def _normalize_header(value: str) -> str:
    return str(value).strip().replace("\\.", ".").lower()


def _header_map(header: list[str]) -> dict[str, int]:
    return {_normalize_header(value): index for index, value in enumerate(header) if str(value).strip()}


def _get(row: list[str], header: dict[str, int], name: str) -> str:
    index = header.get(_normalize_header(name))
    if index is None or index >= len(row):
        return ""
    return row[index].strip()


def parse_linux_apt_timestamp(value: str) -> int:
    text = str(value).strip()
    if not text:
        return 0
    for fmt in ("%b %d, %Y @ %H:%M:%S.%f", "%b %d, %Y @ %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
            return int(parsed.replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            pass
    iso_match = ISO_TIMESTAMP_PATTERN.search(text)
    if iso_match:
        iso_text = iso_match.group(0).replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", iso_text):
            iso_text = f"{iso_text[:-5]}{iso_text[-5:-2]}:{iso_text[-2:]}"
        try:
            parsed = datetime.fromisoformat(iso_text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp())
        except ValueError:
            return 0
    return 0


def _path_action(path_text: str) -> str:
    text = unquote_plus(str(path_text).lower())
    if any(token in text for token in ("<script", "alert(", "document.", "%3cscript")):
        return "xss_probe"
    if any(token in text for token in ("union", "select", "sleep", "concat", "information_schema")):
        return "sql_probe"
    if any(token in text for token in ("../", "..%2f", "/etc/passwd", "boot.ini")):
        return "file_probe"
    if any(token in text for token in ("cmd=", "command=", "<?php", "base64", "bash", "powershell")):
        return "remote_code_probe"
    if "login" in text:
        return "login"
    if "dvwa" in text:
        return "dvwa_request"
    return "request"


def build_linux_apt_template(full_log: str) -> str:
    """Build a low-cardinality template from raw full_log only."""
    text = " ".join(str(full_log).replace("\r", " ").replace("\n", " ").split())
    if not text:
        return "AptLog action=empty"

    apache_match = APACHE_ACCESS_PATTERN.match(text)
    if apache_match:
        method = apache_match.group("method").upper()
        status = apache_match.group("status")
        action = _path_action(apache_match.group("path"))
        return f"AptApache method={method} status={status} action={action}"

    source = classify_linux_log_source(raw_line=text)
    if source:
        return build_linux_event_template(text, source_hint=source)

    lower = text.lower()
    if lower.startswith("ossec:"):
        return f"AptWazuh action={_generic_action(text)}"
    if "integrity checksum changed" in lower:
        return "AptSyscheck action=integrity_checksum_changed"
    if "file added" in lower:
        return "AptSyscheck action=file_added"
    if "file deleted" in lower:
        return "AptSyscheck action=file_deleted"
    if "pam_unix" in lower:
        return f"AptPam action={_generic_action(text)}"
    return f"AptLog action={_generic_action(text)}"


def _generic_action(value: str) -> str:
    text = str(value).lower()
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ip ", text)
    text = re.sub(r"https?://\S+", " url ", text)
    text = re.sub(r"(?:/[\w.\-]+)+", " path ", text)
    text = re.sub(r"\b0x[0-9a-f]+\b", " hex ", text)
    text = re.sub(r"\b\d+\b", " num ", text)
    tokens = re.findall(r"[a-z_]+", text)
    return "_".join(tokens[:6]) if tokens else "message"


def _label_from_value(value: str) -> tuple[str, str]:
    text = str(value).strip().lower()
    if text in {"1", "malicious", "attack", "true", "yes"}:
        return "attack", "malicious"
    return "-", ""


def build_linux_apt_2024_dataset(
    *,
    input_xlsx: Path,
    output_dir: Path,
    log_name: str = DEFAULT_LOG_NAME,
    max_rows: int | None = None,
    summary_path: Path | None = None,
) -> dict[str, Any]:
    input_xlsx = Path(input_xlsx)
    output_dir = Path(output_dir)
    if not input_xlsx.exists():
        raise FileNotFoundError(f"Linux-APT-Dataset-2024 workbook not found: {input_xlsx}")

    row_iter = iter_xlsx_rows(input_xlsx)
    try:
        header = next(row_iter)
    except StopIteration:
        raise ValueError(f"Workbook is empty: {input_xlsx}") from None
    columns = _header_map(header)
    required = {"timestamp", "agent.name", "full_log", "malicious / general"}
    missing = sorted(required - set(columns))
    if missing:
        raise ValueError(f"Workbook missing required columns: {missing}")

    rows: list[dict[str, Any]] = []
    label_counts: Counter[str] = Counter()
    agent_counts: Counter[str] = Counter()
    source_template_counts: Counter[str] = Counter()

    for original_row_number, row in enumerate(row_iter, start=2):
        if max_rows is not None and len(rows) >= max_rows:
            break
        full_log = _get(row, columns, "full_log")
        if not full_log:
            continue

        label, attack_labels = _label_from_value(_get(row, columns, "Malicious / General"))
        agent_name = _get(row, columns, "agent.name") or "linux_apt_host"
        timestamp = parse_linux_apt_timestamp(_get(row, columns, "timestamp"))
        event_template = build_linux_apt_template(full_log)

        rows.append(
            {
                "LineId": len(rows) + 1,
                "Timestamp": timestamp if timestamp > 0 else len(rows) + 1,
                "Label": label,
                "EventTemplate": event_template,
                "Content": full_log,
                "AgentName": agent_name,
                "SourceDataset": "linux_apt_2024",
                "LogSource": "wazuh_full_log",
                "SourceFile": input_xlsx.name,
                "OriginalLineNumber": original_row_number,
                "AttackLabels": attack_labels,
                "RuleDescription": _get(row, columns, "rule.description"),
            }
        )
        label_counts[label] += 1
        agent_counts[agent_name] += 1
        source_template_counts[event_template] += 1

    output_dir.mkdir(parents=True, exist_ok=True)
    structured_path = output_dir / f"{log_name}_structured.csv"
    raw_log_path = output_dir / log_name

    if rows:
        final = pd.DataFrame(rows)
        final = final.sort_values(
            ["AgentName", "Timestamp", "OriginalLineNumber"],
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
                "RuleDescription",
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
                "RuleDescription",
            ]
        )

    final.to_csv(structured_path, index=False)
    raw_log_path.write_text("\n".join(final["Content"].astype(str).tolist()), encoding="utf-8")

    summary = {
        "input_xlsx": input_xlsx,
        "output_dir": output_dir,
        "structured_path": structured_path,
        "log_path": raw_log_path,
        "log_name": log_name,
        "rows": int(len(final)),
        "templates": int(final["EventTemplate"].nunique()) if not final.empty else 0,
        "label_counts": {
            str(key): int(value)
            for key, value in final["Label"].value_counts().to_dict().items()
        }
        if not final.empty
        else {},
        "agent_counts": {
            str(key): int(value)
            for key, value in final["AgentName"].value_counts().to_dict().items()
        }
        if not final.empty
        else {},
        "top_event_templates": (
            final["EventTemplate"].value_counts().head(30).to_dict() if not final.empty else {}
        ),
        "leakage_guard": "EventTemplate is derived from full_log only; MITRE/TTP columns are not used.",
    }
    _write_json(summary_path or output_dir / "linux_apt_2024_summary.json", summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-xlsx", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--log-name", default=DEFAULT_LOG_NAME)
    parser.add_argument("--max-rows", type=int, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = build_linux_apt_2024_dataset(
        input_xlsx=args.input_xlsx,
        output_dir=args.output_dir,
        log_name=args.log_name,
        max_rows=args.max_rows,
    )
    print(json.dumps(summary, indent=2, sort_keys=True, default=_json_default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
