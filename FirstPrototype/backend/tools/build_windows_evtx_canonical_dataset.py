"""Build a DeepLog-ready canonical Windows EVTX training dataset.

This intentionally avoids detection heuristics. It only changes the training
representation so runtime EVTX templates and DeepLog training templates use the
same language.
"""

from __future__ import annotations

import argparse
import json
import random
import xml.etree.ElementTree as ET
from pathlib import Path

import Evtx.Evtx as evtx
import pandas as pd


WINDOWS_APT_COLUMNS = [
    "_source.@timestamp",
    "_source.timestamp",
    "_source.agent.name",
    "_source.rule.mitre.id",
    "_source.rule.mitre.tactic",
    "_source.data.win.system.eventID",
    "_source.data.win.system.providerName",
    "_source.data.win.system.channel",
]

CZ_COLUMNS = [
    "Timestamp",
    "Label",
    "EventID_Windows",
    "Provider",
    "Channel",
    "HostIP",
]

UNK_TOKEN = "<UNK>"
BOS_TOKEN = "<BOS>"
TARGET_SECURITY_EVENT_IDS = {"4661", "5140", "5145", "5156", "5158", "4624", "4672", "4776", "1102"}
WEL_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def normalize(value: object) -> str:
    if value is None:
        return ""
    text = str(value)
    if text.lower() == "nan":
        return ""
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())


def parse_timestamp(value: object, fallback: object = "") -> int:
    for raw_value in (value, fallback):
        text = normalize(raw_value)
        if not text:
            continue
        try:
            if text.isdigit():
                timestamp = int(text)
                return timestamp if timestamp < 10_000_000_000 else timestamp // 1000
            if " @ " in text:
                parsed = pd.to_datetime(
                    text.replace(" @ ", " "),
                    format="%b %d, %Y %H:%M:%S.%f",
                    utc=True,
                    errors="raise",
                )
                return int(parsed.timestamp())
            parsed = pd.to_datetime(text, utc=True, errors="raise")
            return int(parsed.timestamp())
        except Exception:
            continue
    return 0


def canonical_template(event_id: object, provider: object, channel: object) -> str:
    event_id_text = normalize(event_id) or "UNKNOWN"
    provider_text = normalize(provider) or "Unknown"
    channel_text = normalize(channel) or "Unknown"
    return f"EventID {event_id_text} Provider {provider_text} Channel {channel_text}"


def load_windows_apt_benign(path: Path) -> pd.DataFrame:
    df = pd.read_csv(
        path,
        usecols=WINDOWS_APT_COLUMNS,
        low_memory=False,
        on_bad_lines="skip",
        encoding="utf-8-sig",
    )
    for column in WINDOWS_APT_COLUMNS:
        df[column] = df[column].map(normalize)

    mitre_signal = (
        df["_source.rule.mitre.id"].str.strip()
        + df["_source.rule.mitre.tactic"].str.strip()
    )
    windows_rows = (
        df["_source.data.win.system.eventID"].str.strip().ne("")
        & df["_source.data.win.system.providerName"].str.strip().ne("")
        & df["_source.data.win.system.channel"].str.strip().ne("")
    )
    benign_rows = mitre_signal.str.strip().eq("")
    df = df[windows_rows & benign_rows].copy()

    output = pd.DataFrame()
    output["Timestamp"] = df.apply(
        lambda row: parse_timestamp(row["_source.@timestamp"], row["_source.timestamp"]),
        axis=1,
    )
    output["Label"] = "-"
    output["EventTemplate"] = df.apply(
        lambda row: canonical_template(
            row["_source.data.win.system.eventID"],
            row["_source.data.win.system.providerName"],
            row["_source.data.win.system.channel"],
        ),
        axis=1,
    )
    output["Content"] = output["EventTemplate"]
    output["AgentName"] = df["_source.agent.name"].replace("", "windows_apt")
    output["SourceDataset"] = "windows_apt_benign"
    return output[output["Timestamp"] > 0]


def load_czmuni_normal(path: Path, max_rows: int | None) -> pd.DataFrame:
    chunks = []
    remaining = max_rows
    for chunk in pd.read_csv(path, usecols=CZ_COLUMNS, chunksize=200_000, low_memory=False):
        if remaining is not None and remaining <= 0:
            break

        chunk = chunk.fillna("")
        chunk = chunk[chunk["EventID_Windows"].map(normalize).ne("")]
        chunk = chunk[chunk["Provider"].map(normalize).ne("")]
        chunk = chunk[chunk["Channel"].map(normalize).ne("")]
        chunk = chunk[chunk["Label"].map(normalize).eq("-")]
        if remaining is not None:
            chunk = chunk.head(remaining)
            remaining -= len(chunk)
        chunks.append(chunk)

    if not chunks:
        return pd.DataFrame(
            columns=["Timestamp", "Label", "EventTemplate", "Content", "AgentName", "SourceDataset"]
        )

    df = pd.concat(chunks, ignore_index=True)
    output = pd.DataFrame()
    output["Timestamp"] = df["Timestamp"].map(lambda value: parse_timestamp(value))
    output["Label"] = "-"
    output["EventTemplate"] = df.apply(
        lambda row: canonical_template(row["EventID_Windows"], row["Provider"], row["Channel"]),
        axis=1,
    )
    output["Content"] = output["EventTemplate"]
    output["AgentName"] = df["HostIP"].map(normalize).replace("", "czmuni")
    output["SourceDataset"] = "czmuni_winlog"
    return output[output["Timestamp"] > 0]


def _evtx_text(root: ET.Element, path: str, default: str = "") -> str:
    element = root.find(path, WEL_NS)
    if element is None:
        return default
    return normalize(element.text or default)


def _evtx_attr(root: ET.Element, path: str, attr: str, default: str = "") -> str:
    element = root.find(path, WEL_NS)
    if element is None:
        return default
    return normalize(element.get(attr, default))


def _parse_evtx_record(xml_text: str, fallback_timestamp: int = 0) -> dict[str, str | int]:
    root = ET.fromstring(xml_text)
    timestamp_text = _evtx_attr(root, "e:System/e:TimeCreated", "SystemTime")
    return {
        "timestamp": parse_timestamp(timestamp_text) or fallback_timestamp,
        "event_id": _evtx_text(root, "e:System/e:EventID", "UNKNOWN"),
        "provider": _evtx_attr(root, "e:System/e:Provider", "Name", "Unknown"),
        "channel": _evtx_text(root, "e:System/e:Channel", "Unknown"),
        "computer": _evtx_text(root, "e:System/e:Computer", "normal_evtx"),
    }


def load_normal_evtx_dir(
    evtx_dir: Path | None,
    glob_pattern: str,
    max_files: int | None,
    max_records_per_file: int | None,
    source_name: str,
) -> pd.DataFrame:
    if evtx_dir is None or not evtx_dir.exists():
        return pd.DataFrame(
            columns=["Timestamp", "Label", "EventTemplate", "Content", "AgentName", "SourceDataset"]
        )

    rows: list[dict[str, object]] = []
    files = sorted(evtx_dir.rglob(glob_pattern))
    if max_files is not None:
        files = files[:max_files]

    for file_path in files:
        try:
            with evtx.Evtx(str(file_path)) as log:
                for idx, record in enumerate(log.records(), start=1):
                    if max_records_per_file is not None and idx > max_records_per_file:
                        break
                    try:
                        parsed = _parse_evtx_record(record.xml(), fallback_timestamp=idx)
                    except Exception:
                        continue
                    template = canonical_template(
                        parsed["event_id"],
                        parsed["provider"],
                        parsed["channel"],
                    )
                    rows.append(
                        {
                            "Timestamp": parsed["timestamp"],
                            "Label": "-",
                            "EventTemplate": template,
                            "Content": template,
                            "AgentName": normalize(parsed["computer"]) or file_path.stem,
                            "SourceDataset": source_name,
                        }
                    )
        except Exception as exc:
            print(f"Skipping EVTX {file_path}: {exc}")

    return pd.DataFrame(rows)


def apply_unknown_burst_augmentation(
    df: pd.DataFrame,
    burst_probability: float,
    min_burst: int,
    max_burst: int,
    seed: int,
) -> pd.DataFrame:
    rng = random.Random(seed)
    augmented_parts = []

    for _, host_df in df.groupby("AgentName", sort=False):
        host_df = host_df.copy().reset_index(drop=True)
        mask = [False] * len(host_df)
        idx = 0
        while idx < len(host_df):
            if rng.random() < burst_probability:
                burst_len = rng.randint(min_burst, max_burst)
                for burst_idx in range(idx, min(len(host_df), idx + burst_len)):
                    mask[burst_idx] = True
                idx += burst_len
            else:
                idx += 1
        host_df.loc[mask, "EventTemplate"] = UNK_TOKEN
        host_df.loc[mask, "Content"] = UNK_TOKEN
        augmented_parts.append(host_df)

    return pd.concat(augmented_parts, ignore_index=True)


def add_bos_session_context(
    df: pd.DataFrame,
    bos_token: str,
    bos_count: int,
    session_event_count: int,
) -> pd.DataFrame:
    """Prepend BOS context to pseudo-sessions so short logs can be modelled.

    The training loader groups Windows-APT data by AgentName. We therefore
    encode each host chunk as a separate pseudo-session in AgentName and prepend
    BOS rows to every chunk. This keeps DeepLog sequence learning in the model,
    while avoiding event-specific detection logic.
    """
    if bos_count <= 0:
        return df
    if session_event_count <= 0:
        raise ValueError("--bos-session-event-count must be > 0")

    parts: list[pd.DataFrame] = []
    for host_name, host_df in df.groupby("AgentName", sort=False):
        host_df = host_df.sort_values("Timestamp", kind="stable").reset_index(drop=True)
        for chunk_index, start in enumerate(range(0, len(host_df), session_event_count)):
            chunk_df = host_df.iloc[start : start + session_event_count].copy()
            if chunk_df.empty:
                continue

            session_name = f"{host_name}#session{chunk_index:06d}"
            first_timestamp = int(chunk_df["Timestamp"].iloc[0])
            bos_rows = [
                {
                    "Timestamp": first_timestamp - bos_count + offset,
                    "Label": "-",
                    "EventTemplate": bos_token,
                    "Content": bos_token,
                    "AgentName": session_name,
                    "SourceDataset": "bos_context",
                }
                for offset in range(bos_count)
            ]
            chunk_df["AgentName"] = session_name
            parts.append(pd.concat([pd.DataFrame(bos_rows), chunk_df], ignore_index=True))

    if not parts:
        return df
    return pd.concat(parts, ignore_index=True)


def write_outputs(
    df: pd.DataFrame,
    output_dir: Path,
    log_name: str,
    bos_token: str = BOS_TOKEN,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    structured_path = output_dir / f"{log_name}_structured.csv"
    log_path = output_dir / log_name

    final = df.sort_values(["AgentName", "Timestamp"], kind="stable").reset_index(drop=True)
    final["EventId"] = pd.factorize(final["EventTemplate"])[0] + 1
    final = final[
        ["Timestamp", "Label", "EventId", "EventTemplate", "Content", "AgentName", "SourceDataset"]
    ]
    final.to_csv(structured_path, index=False)
    log_path.write_text("\n".join(final["Content"].astype(str).tolist()), encoding="utf-8")

    summary = {
        "rows": int(len(final)),
        "templates": int(final["EventTemplate"].nunique()),
        "sources": final["SourceDataset"].value_counts().to_dict(),
        "top_templates": final["EventTemplate"].value_counts().head(30).to_dict(),
        "target_security_event_templates": {
            event_id: int(
                final["EventTemplate"].str.contains(
                    f"EventID {event_id} ",
                    regex=False,
                ).sum()
            )
            for event_id in sorted(TARGET_SECURITY_EVENT_IDS)
        },
        "unk_rows": int((final["EventTemplate"] == UNK_TOKEN).sum()),
        "bos_rows": int((final["EventTemplate"] == bos_token).sum()),
        "bos_sessions": int(
            final.loc[
                final["AgentName"].astype(str).str.contains("#session", regex=False),
                "AgentName",
            ].nunique()
        ),
    }
    (output_dir / "windows_evtx_canonical_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    return structured_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--windows-apt",
        default=r"D:\Dataset\Windows-APT 2025 A Dataset for APT-Inspired Attack\combined.csv",
    )
    parser.add_argument(
        "--czmuni",
        default=r"D:\FAKI\NEWMLMODL\dataset\czmuni\winlog.log_structured.csv",
    )
    parser.add_argument(
        "--output-dir",
        default=r"D:\FAKI\NEWMLMODL\dataset\windows_evtx_canonical",
    )
    parser.add_argument("--log-name", default="windows_evtx_canonical.log")
    parser.add_argument("--czmuni-max-rows", type=int, default=500_000)
    parser.add_argument("--normal-evtx-dir", default="")
    parser.add_argument("--normal-evtx-glob", default="*.evtx")
    parser.add_argument("--normal-evtx-max-files", type=int, default=None)
    parser.add_argument("--normal-evtx-max-records-per-file", type=int, default=None)
    parser.add_argument("--normal-evtx-source-name", default="normal_security_evtx")
    parser.add_argument("--unk-burst-probability", type=float, default=0.025)
    parser.add_argument("--unk-burst-min", type=int, default=2)
    parser.add_argument("--unk-burst-max", type=int, default=8)
    parser.add_argument("--enable-bos-context", action="store_true")
    parser.add_argument("--bos-token", default=BOS_TOKEN)
    parser.add_argument("--bos-count", type=int, default=20)
    parser.add_argument("--bos-session-event-count", type=int, default=40)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    windows_apt_df = load_windows_apt_benign(Path(args.windows_apt))
    czmuni_df = load_czmuni_normal(Path(args.czmuni), args.czmuni_max_rows)
    normal_evtx_df = load_normal_evtx_dir(
        Path(args.normal_evtx_dir) if args.normal_evtx_dir else None,
        glob_pattern=args.normal_evtx_glob,
        max_files=args.normal_evtx_max_files,
        max_records_per_file=args.normal_evtx_max_records_per_file,
        source_name=args.normal_evtx_source_name,
    )
    combined = pd.concat([windows_apt_df, czmuni_df, normal_evtx_df], ignore_index=True)
    augmented = apply_unknown_burst_augmentation(
        combined,
        burst_probability=args.unk_burst_probability,
        min_burst=args.unk_burst_min,
        max_burst=args.unk_burst_max,
        seed=args.seed,
    )
    if args.enable_bos_context:
        augmented = add_bos_session_context(
            augmented,
            bos_token=args.bos_token,
            bos_count=args.bos_count,
            session_event_count=args.bos_session_event_count,
        )
    path = write_outputs(augmented, Path(args.output_dir), args.log_name, bos_token=args.bos_token)
    print(path)


if __name__ == "__main__":
    main()
