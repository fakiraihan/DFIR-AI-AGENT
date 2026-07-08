"""Deterministic Linux log templates for AIT-LDS/Kyoushi-style logs."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RFC3164_PATTERN = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[A-Za-z0-9_.@/+:\-()]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)
AUDIT_EPOCH_PATTERN = re.compile(r"\baudit\((?P<epoch>\d+(?:\.\d+)?):\d+\)")
KEY_VALUE_PATTERN = re.compile(
    r"\b(?P<key>[A-Za-z_][\w.-]*)=(?P<value>\"[^\"]*\"|'[^']*'|[^\s;]+)"
)
MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def classify_linux_log_path(path: str | Path) -> str | None:
    """Return the supported AIT-LDS log source for a path, if any."""
    path_obj = Path(path)
    name = path_obj.name.lower()
    if name.startswith("auth.log"):
        return "auth"
    if name.startswith("syslog"):
        return "syslog"
    if name.startswith("audit.log"):
        return "audit"
    return None


def classify_linux_log_source(
    path: str | Path | None = None,
    raw_line: str | None = None,
) -> str | None:
    """Classify a log line/path into auth, audit, or syslog."""
    if path is not None:
        source = classify_linux_log_path(path)
        if source:
            return source
    text = (raw_line or "").strip()
    if text.startswith("type=") or " msg=audit(" in text:
        return "audit"
    match = RFC3164_PATTERN.match(text)
    if match:
        process = _normalize_process(match.group("process"))
        if process in {"sshd", "sudo", "su", "cron", "pam_unix", "systemd-logind"}:
            return "auth"
        return "syslog"
    return None


def build_linux_event_template(raw_line: str, source_hint: str | None = None) -> str:
    """Build a stable, low-cardinality template for Linux DeepLog training/runtime."""
    source = (source_hint or classify_linux_log_source(raw_line=raw_line) or "linux").lower()
    text = _normalize_space(raw_line)
    if source == "audit" or text.startswith("type="):
        return _build_audit_template(text)
    return _build_rfc3164_template(text, source)


def parse_linux_timestamp(raw_line: str, *, default_year: int = 2022) -> int:
    """Parse common AIT-LDS Linux timestamps into epoch seconds."""
    text = raw_line.strip()
    audit_match = AUDIT_EPOCH_PATTERN.search(text)
    if audit_match:
        return int(float(audit_match.group("epoch")))

    match = RFC3164_PATTERN.match(text)
    if match:
        stamp = match.group("stamp")
        month_name, day, time_text = stamp.split()
        hour, minute, second = [int(part) for part in time_text.split(":")]
        dt = datetime(
            int(default_year),
            MONTHS[month_name],
            int(day),
            hour,
            minute,
            second,
            tzinfo=timezone.utc,
        )
        return int(dt.timestamp())

    iso_match = re.search(
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
        text,
    )
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


_TRUSTED_EXE_PREFIXES = (
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib64/",
    "/snap/",
    "/var/ossec/bin/",
)


def _exe_template_value(value: str) -> str:
    """Collapse executables running from standard system directories.

    Execution from a well-known system path (package binaries, systemd
    generators, security-agent installs, ...) is routine and otherwise
    creates hundreds of distinct-but-benign template variants (one per
    binary name) purely from normal system/package noise. Execution from
    anywhere else (/tmp, a user home directory, /opt, ...) is the actually
    anomalous signal worth keeping distinct for APT detection.
    """
    text = str(value).strip().strip("\"'")
    if not text:
        return "unknown"
    if text.startswith(_TRUSTED_EXE_PREFIXES):
        return "<sys>"
    return _basename(text)


def _build_audit_template(text: str) -> str:
    values = _parse_key_values(text)
    for inner_msg in re.findall(r"\bmsg=(['\"])(.*?)\1", text):
        values.update(_parse_key_values(inner_msg[1]))

    parts = ["LinuxAudit", f"type={values.get('type', 'unknown')}"]
    if values.get("op"):
        parts.append(f"op={values['op']}")
    if values.get("syscall"):
        parts.append(f"syscall={values['syscall']}")
    if values.get("exe"):
        parts.append(f"exe={_exe_template_value(values['exe'])}")
    if values.get("res"):
        parts.append(f"res={values['res']}")
    elif values.get("success"):
        parts.append(f"success={values['success']}")
    return " ".join(parts)


def _build_rfc3164_template(text: str, source: str) -> str:
    match = RFC3164_PATTERN.match(text)
    prefix = (
        "LinuxAuth"
        if source == "auth"
        else "LinuxSyslog"
        if source == "syslog"
        else "LinuxLog"
    )
    if not match:
        return f"{prefix} process=unknown action={_generic_action(text)}"

    process = _normalize_process(match.group("process"))
    message = _normalize_space(match.group("message"))
    action = (
        _auth_action(process, message)
        if source == "auth"
        else _syslog_action(process, message)
    )
    return f"{prefix} process={process} action={action}"


def _auth_action(process: str, message: str) -> str:
    lower = message.lower()
    if process == "sudo" and "command=" in lower:
        return "sudo_command"
    if "successful su for" in lower:
        return "su_success"
    if "failed password" in lower:
        return "ssh_failed_password"
    if "accepted password" in lower:
        return "ssh_accepted_password"
    if "accepted publickey" in lower:
        return "ssh_accepted_publickey"
    if "invalid user" in lower:
        return "ssh_invalid_user"
    if "authentication failure" in lower:
        return "pam_auth_failure"
    if "session opened" in lower:
        return "cron_session_open" if process == "cron" else "pam_session_open"
    if "session closed" in lower:
        return "cron_session_close" if process == "cron" else "pam_session_close"
    if "new session" in lower:
        return "systemd_new_session"
    if "removed session" in lower:
        return "systemd_removed_session"
    return _generic_action(message)


def _syslog_action(process: str, message: str) -> str:
    lower = message.lower()
    if lower.startswith("started session"):
        return "started_session"
    if lower.startswith("removed session"):
        return "removed_session"
    if lower.startswith("started "):
        return "started_unit"
    if lower.startswith("stopped "):
        return "stopped_unit"
    if "failed" in lower:
        return "failed"
    return _generic_action(message)


def _generic_action(message: str) -> str:
    text = message.lower()
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ip ", text)
    text = re.sub(r"https?://\S+", " url ", text)
    text = re.sub(r"(?:/[\w.\-]+)+", " path ", text)
    text = re.sub(r"\b0x[0-9a-f]+\b", " hex ", text)
    text = re.sub(r"\b\d+\b", " num ", text)
    tokens = re.findall(r"[a-z_]+", text)
    return "_".join(tokens[:6]) if tokens else "message"


def _parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for match in KEY_VALUE_PATTERN.finditer(text):
        key = match.group("key")
        value = match.group("value").strip().strip("\"'")
        values[key] = value
    return values


def _basename(value: Any) -> str:
    text = str(value).strip().strip("\"'")
    if not text:
        return "unknown"
    return Path(text).name or text


def _normalize_process(value: str) -> str:
    process = value.strip().lower()
    process = re.sub(r"\([^)]*\)$", "", process)
    if process == "cron":
        return "cron"
    return process


def _normalize_space(value: str) -> str:
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())
