"""IOC classification and extraction helpers for the DFIR agent."""

import json
import re
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlparse

import pandas as pd


IdentifyIocType = Callable[[str], Optional[str]]


def identify_ioc_type(value: str, executable_file_extensions: Set[str]) -> Optional[str]:
    """Identify supported IOC type from a raw token."""
    normalized_value = str(value or "").strip()
    if not normalized_value:
        return None

    lowered = normalized_value.lower()

    try:
        ip_address(normalized_value)
        return "ip"
    except ValueError:
        pass

    if normalized_value.startswith(("http://", "https://")):
        parsed_url = urlparse(normalized_value)
        if parsed_url.scheme and parsed_url.netloc:
            return "url"

    if re.fullmatch(r"[a-fA-F0-9]{64}", normalized_value):
        return "sha256"

    if re.fullmatch(r"[a-fA-F0-9]{32}", normalized_value):
        return "md5"

    if any(char in normalized_value for char in ("\\", "/", ":", " ")):
        return None

    if looks_like_filename(lowered, executable_file_extensions):
        return None

    if looks_like_script_token(normalized_value):
        return None

    if re.fullmatch(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}", normalized_value):
        return "domain"

    return None


def looks_like_filename(value: str, executable_file_extensions: Set[str]) -> bool:
    """Return true for tokens that are filenames rather than domains."""
    file_suffix = Path(value).suffix.lower()
    if file_suffix in executable_file_extensions:
        return True
    return value in {"localhost", "localdomain"}


def looks_like_script_token(value: str) -> bool:
    """Return true for script/COM tokens that resemble dotted domains."""
    parts = value.split(".")
    if len(parts) < 2:
        return False

    if not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", part) for part in parts):
        return False

    lowered_parts = [part.lower() for part in parts]
    first_part = lowered_parts[0]
    last_part = lowered_parts[-1]

    if first_part in {"wscript", "cscript"} and last_part in {
        "shell",
        "createobject",
        "network",
    }:
        return True

    if first_part in {"objshell", "wshshell", "shell"} and last_part in {
        "run",
        "exec",
        "expandenvironmentstrings",
        "regread",
        "regwrite",
        "regdelete",
        "specialfolders",
        "environment",
        "application",
    }:
        return True

    if first_part == "scripting" and last_part == "filesystemobject":
        return True

    if first_part == "adodb" and last_part in {"stream", "connection", "recordset"}:
        return True

    if first_part.startswith("obj") and last_part in {"run", "exec"}:
        return True

    return False


def extract_iocs_from_anomalies(
    anomalies: List[Dict[str, Any]],
    parsed_logs: pd.DataFrame,
    identify_ioc_type_fn: IdentifyIocType,
) -> List[Dict[str, Any]]:
    """Extract unique IOCs from anomaly windows in parsed log rows."""
    iocs = []

    for anomaly in anomalies:
        start_idx = anomaly["start_idx"]
        end_idx = anomaly["end_idx"]
        window_logs = parsed_logs.iloc[start_idx : end_idx + 1]

        for _, log_entry in window_logs.iterrows():
            params = json.loads(log_entry.get("parameters", "[]"))

            for param in params:
                ioc_type = identify_ioc_type_fn(param)
                if ioc_type:
                    iocs.append(
                        {
                            "value": param,
                            "type": ioc_type,
                            "source_line": log_entry["event_id"],
                            "window_id": anomaly["window_id"],
                        }
                    )

    unique_iocs = []
    seen = set()
    for ioc in iocs:
        key = f"{ioc['type']}:{ioc['value']}"
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

    return unique_iocs
