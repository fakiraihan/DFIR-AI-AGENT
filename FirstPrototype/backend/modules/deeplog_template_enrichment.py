"""Deterministic template enrichment for DeepLog retraining.

The goal is to give DeepLog more sequence signal without turning high-cardinality
raw values into vocabulary tokens. Every emitted token is a small bucket.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from pathlib import PureWindowsPath
from typing import Any

import pandas as pd


ENRICHMENT_NONE = {"", "none", "off", "disabled"}
ENRICHMENT_LMD_SYSMON_V1 = "lmd_sysmon_v1"

KEY_VALUE_PATTERN = re.compile(
    r"\b(?P<key>[A-Za-z_][\w.-]{0,63})="
    r"(?P<value>\"[^\"]*\"|'[^']*'|.*?)(?=\s+[A-Za-z_][\w.-]{0,63}=|$)"
)
EVENT_ID_PATTERN = re.compile(r"\bEventID(?:=|\s+)(?P<event_id>\d+)", re.IGNORECASE)


def is_enrichment_enabled(mode: str | None) -> bool:
    return str(mode or "").strip().lower() not in ENRICHMENT_NONE


def normalize_enrichment_mode(mode: str | None) -> str:
    normalized = str(mode or "none").strip().lower()
    if normalized in ENRICHMENT_NONE:
        return "none"
    if normalized in {ENRICHMENT_LMD_SYSMON_V1, "sysmon_lmd_v1", "lmd2023_sysmon_v1"}:
        return ENRICHMENT_LMD_SYSMON_V1
    raise ValueError(
        f"Unsupported DeepLog template enrichment mode: {mode!r}. "
        f"Supported: none, {ENRICHMENT_LMD_SYSMON_V1}"
    )


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    if text.lower() == "nan":
        return ""
    return " ".join(text.split())


def _row_get(row: Mapping[str, Any] | pd.Series, *keys: str) -> Any:
    for key in keys:
        if key in row:
            value = row[key]
            if _clean_text(value):
                return value
    return ""


def parse_key_values(text: Any) -> dict[str, str]:
    """Parse Sysmon-style key=value fields while preserving quoted spaces."""
    source = _clean_text(text)
    fields: dict[str, str] = {}
    for match in KEY_VALUE_PATTERN.finditer(source):
        key = match.group("key")
        value = match.group("value").strip().strip('"').strip("'")
        if key and value and key not in fields:
            fields[key] = value
    return fields


def _event_id_from_row(row: Mapping[str, Any] | pd.Series, fields: dict[str, str]) -> str:
    for key in ("EventID", "EventId", "event_id", "EventID_Windows"):
        raw_value = _clean_text(row[key]) if key in row else ""
        if raw_value:
            try:
                return str(int(float(raw_value)))
            except ValueError:
                return raw_value

    field_value = _clean_text(fields.get("EventID"))
    if field_value:
        return field_value

    template = _clean_text(_row_get(row, "EventTemplate", "event_template"))
    match = EVENT_ID_PATTERN.search(template)
    return match.group("event_id") if match else "UNKNOWN"


def _base_template(row: Mapping[str, Any] | pd.Series, event_id: str) -> str:
    template = _clean_text(_row_get(row, "OriginalEventTemplate", "EventTemplate", "event_template"))
    match = EVENT_ID_PATTERN.search(template)
    if match:
        provider = template[: match.start()].strip() or "Microsoft-Windows-Sysmon"
        return f"{provider} EventID={event_id}"
    return f"Microsoft-Windows-Sysmon EventID={event_id}"


def _windows_basename(value: str) -> str:
    text = _clean_text(value).strip('"').strip("'")
    if not text:
        return ""
    if text.lower() == "system":
        return "system"
    return PureWindowsPath(text).name.lower()


def _stem(value: str) -> str:
    base = _windows_basename(value)
    return base[:-4] if base.endswith(".exe") else base


def classify_process_image(value: Any) -> str:
    text = _clean_text(value).lower()
    if not text:
        return "unknown"
    if text == "system":
        return "system"

    stem = _stem(text)
    known = {
        "powershell": "powershell",
        "pwsh": "powershell",
        "cmd": "cmd",
        "rundll32": "rundll32",
        "regsvr32": "regsvr32",
        "wscript": "script_host",
        "cscript": "script_host",
        "mshta": "mshta",
        "certutil": "certutil",
        "bitsadmin": "bitsadmin",
        "schtasks": "schtasks",
        "wmic": "wmic",
        "psexec": "remote_admin",
        "paexec": "remote_admin",
        "procdump": "dump_tool",
        "lsass": "lsass",
        "svchost": "windows_service",
        "services": "windows_service",
        "winlogon": "windows_service",
        "explorer": "explorer",
        "chrome": "browser",
        "msedge": "browser",
        "firefox": "browser",
    }
    if stem in known:
        return known[stem]
    if "\\users\\" in text and ("\\temp\\" in text or "\\appdata\\local\\temp\\" in text):
        return "user_temp"
    if "\\users\\" in text:
        return "user_path"
    if "\\program files" in text:
        return "program_files"
    if "\\windows\\" in text:
        return "windows"
    return "other"


def classify_user(value: Any) -> str:
    text = _clean_text(value).lower()
    if not text:
        return "unknown"
    if "nt authority\\system" in text or text.endswith("\\system") or text == "system":
        return "system"
    if "network service" in text:
        return "network_service"
    if "local service" in text:
        return "local_service"
    if text.endswith("$"):
        return "machine"
    return "user"


def classify_ip(value: Any) -> str:
    text = _clean_text(value)
    if not text:
        return "unknown"
    try:
        ip_obj = ipaddress.ip_address(text)
    except ValueError:
        return "hostname"
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_link_local:
        return "link_local"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_private:
        return "private"
    return "public"


def classify_port(value: Any) -> str:
    text = _clean_text(value)
    if not text:
        return "unknown"
    try:
        port = int(float(text))
    except ValueError:
        return "unknown"
    named_ports = {
        53: "dns",
        80: "web",
        443: "web",
        445: "smb",
        139: "smb",
        135: "rpc",
        3389: "rdp",
        5985: "winrm",
        5986: "winrm",
        389: "ldap",
        636: "ldap",
        88: "kerberos",
        22: "ssh",
        25: "smtp",
    }
    if port in named_ports:
        return named_ports[port]
    if port < 1024:
        return "privileged"
    if port < 49152:
        return "high"
    return "ephemeral"


def classify_command(value: Any) -> str:
    text = _clean_text(value).lower()
    if not text:
        return "empty"
    if "encodedcommand" in text or re.search(r"\s-enc(?:odedcommand)?\b", text):
        return "encoded"
    if any(token in text for token in ("downloadstring", "invoke-webrequest", "curl ", "wget ")):
        return "download"
    if any(token in text for token in ("bypass", "hidden", " -nop", " -w hidden")):
        return "suspicious"
    if any(token in text for token in ("whoami", " nltest", " net view", " net user", " ipconfig")):
        return "discovery"
    return "other"


def classify_access(value: Any) -> str:
    text = _clean_text(value).lower()
    if not text:
        return "unknown"
    try:
        access = int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return "unknown"
    high_masks = (0x0010, 0x0400, 0x1000, 0x1F0000)
    if any(access & mask for mask in high_masks):
        return "high"
    return "low"


def classify_path(value: Any) -> str:
    text = _clean_text(value).lower()
    if not text:
        return "unknown"
    if "\\users\\" in text and ("\\temp\\" in text or "\\appdata\\local\\temp\\" in text):
        return "user_temp"
    if "\\users\\" in text:
        return "user_path"
    if "\\windows\\" in text:
        return "windows"
    if "\\program files" in text:
        return "program_files"
    return "other"


def classify_registry(value: Any) -> str:
    text = _clean_text(value).lower()
    if not text:
        return "unknown"
    if "currentversion\\run" in text or "\\runonce" in text:
        return "autorun"
    if "\\services\\" in text:
        return "services"
    if "\\sam\\" in text or "\\security\\" in text:
        return "sensitive"
    if text.startswith("hklm") or "\\hkey_local_machine\\" in text:
        return "hklm"
    if text.startswith("hkcu") or "\\hkey_current_user\\" in text:
        return "hkcu"
    return "other"


def classify_query(value: Any) -> str:
    text = _clean_text(value).lower().rstrip(".")
    if not text:
        return "unknown"
    if text.endswith(".local") or ".local." in text or text.endswith(".lan"):
        return "internal"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):
        return classify_ip(text)
    return "domain"


def _first_field(fields: dict[str, str], *keys: str) -> str:
    for key in keys:
        value = _clean_text(fields.get(key))
        if value:
            return value
    return ""


def _append(parts: list[str], key: str, value: str) -> None:
    parts.append(f"{key}={value or 'unknown'}")


def enrich_event_template(row: Mapping[str, Any] | pd.Series, mode: str | None = ENRICHMENT_LMD_SYSMON_V1) -> str:
    """Return an enriched, low-cardinality DeepLog template for one row."""
    mode_name = normalize_enrichment_mode(mode)
    original = _clean_text(_row_get(row, "EventTemplate", "event_template"))
    if mode_name == "none":
        return original

    raw_line = _clean_text(_row_get(row, "Content", "raw_line", "Message", "message")) or original
    fields = parse_key_values(raw_line)
    event_id = _event_id_from_row(row, fields)
    parts = [_base_template(row, event_id)]

    image = _first_field(fields, "Image")
    user = _first_field(fields, "User")

    if event_id == "1":
        _append(parts, "ImageClass", classify_process_image(image))
        _append(parts, "CmdClass", classify_command(_first_field(fields, "CommandLine")))
        _append(parts, "ParentClass", classify_process_image(_first_field(fields, "ParentImage")))
        _append(parts, "UserClass", classify_user(user))
    elif event_id == "3":
        _append(parts, "ImageClass", classify_process_image(image))
        _append(parts, "UserClass", classify_user(user))
        _append(parts, "DestinationClass", classify_ip(_first_field(fields, "DestinationIp", "DestinationHostname")))
        _append(parts, "DestinationPortClass", classify_port(_first_field(fields, "DestinationPort")))
    elif event_id == "5":
        _append(parts, "ImageClass", classify_process_image(image))
        _append(parts, "UserClass", classify_user(user))
    elif event_id == "7":
        _append(parts, "ImageClass", classify_process_image(image))
        _append(parts, "LoadedImageClass", classify_path(_first_field(fields, "ImageLoaded")))
        _append(parts, "UserClass", classify_user(user))
    elif event_id == "10":
        _append(parts, "SourceClass", classify_process_image(_first_field(fields, "SourceImage")))
        _append(parts, "TargetClass", classify_process_image(_first_field(fields, "TargetImage")))
        _append(parts, "AccessClass", classify_access(_first_field(fields, "GrantedAccess")))
        _append(parts, "UserClass", classify_user(user))
    elif event_id == "11":
        _append(parts, "ImageClass", classify_process_image(image))
        _append(parts, "TargetPathClass", classify_path(_first_field(fields, "TargetFilename")))
        _append(parts, "UserClass", classify_user(user))
    elif event_id in {"12", "13", "14"}:
        _append(parts, "ImageClass", classify_process_image(image))
        _append(parts, "RegistryClass", classify_registry(_first_field(fields, "TargetObject")))
        _append(parts, "UserClass", classify_user(user))
    elif event_id == "22":
        _append(parts, "ImageClass", classify_process_image(image))
        _append(parts, "QueryClass", classify_query(_first_field(fields, "QueryName")))
        _append(parts, "UserClass", classify_user(user))
    elif event_id == "23":
        _append(parts, "ImageClass", classify_process_image(image))
        _append(parts, "TargetPathClass", classify_path(_first_field(fields, "TargetFilename")))
        _append(parts, "UserClass", classify_user(user))
    else:
        if image:
            _append(parts, "ImageClass", classify_process_image(image))
        if user:
            _append(parts, "UserClass", classify_user(user))

    return " ".join(parts)


def enrich_structured_dataframe(
    df: pd.DataFrame,
    mode: str | None = ENRICHMENT_LMD_SYSMON_V1,
    *,
    preserve_original_template: bool = True,
) -> pd.DataFrame:
    """Return a dataframe with enriched EventTemplate/event_template columns."""
    mode_name = normalize_enrichment_mode(mode)
    if df.empty or mode_name == "none":
        return df.copy()

    enriched = df.copy()
    original_column = "EventTemplate" if "EventTemplate" in enriched.columns else "event_template"
    if preserve_original_template and "OriginalEventTemplate" not in enriched.columns:
        enriched["OriginalEventTemplate"] = enriched.get(original_column, "")

    new_templates = [
        enrich_event_template(row, mode=mode_name)
        for _, row in enriched.iterrows()
    ]
    if "EventTemplate" in enriched.columns or "event_template" not in enriched.columns:
        enriched["EventTemplate"] = new_templates
    if "event_template" in enriched.columns:
        enriched["event_template"] = new_templates
    return enriched


def summarize_templates(df: pd.DataFrame) -> list[dict[str, Any]]:
    if df.empty or "event_template" not in df.columns:
        return []
    grouped = (
        df.groupby("event_template", dropna=False)
        .size()
        .reset_index(name="size")
        .sort_values(["size", "event_template"], ascending=[False, True])
    )
    return [
        {
            "cluster_id": str(row["event_template"]),
            "template": str(row["event_template"]),
            "size": int(row["size"]),
        }
        for _, row in grouped.iterrows()
    ]
