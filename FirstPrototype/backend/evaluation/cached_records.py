"""Helpers for DeepLog evaluation on cached training/eval records."""

from __future__ import annotations

import gzip
import pickle
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


DEFAULT_CACHED_CONFIG = Path(
    r"D:\FAKI\NEWMLMODL\config\deeplog_lmd2023_2_3m_per_host.yaml"
)
DEFAULT_CACHED_TOPK_VALUES = (3, 5, 9)


@dataclass(frozen=True)
class CachedSession:
    sequence: list[str]
    label: int
    count: int = 1


@dataclass(frozen=True)
class CachedWindow:
    session_idx: int
    window_idx: int
    history: list[str]
    target: str


def _parse_scalar(value: str) -> Any:
    text = value.strip().strip("'\"")
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"none", "null"}:
        return None
    try:
        if "." not in text:
            return int(text)
        return float(text)
    except ValueError:
        return text


def _simple_yaml_load(path: Path) -> dict[str, Any]:
    config: dict[str, Any] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        config[key.strip()] = _parse_scalar(value)
    return config


def load_yaml_config(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore

        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        return dict(payload or {})
    except ImportError:
        return _simple_yaml_load(path)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _resolve_relative_to_config(path_value: Any, config_path: Path | None) -> Path:
    path = Path(str(path_value))
    if path.is_absolute():
        return path
    if config_path is None:
        return path.resolve()
    return (config_path.resolve().parent.parent / path).resolve()


def compose_cached_run_dir(
    config: dict[str, Any],
    *,
    config_path: Path | None = None,
) -> Path:
    output_dir = _resolve_relative_to_config(config["output_dir"], config_path)
    dataset_name = str(config["dataset_name"])
    grouping = str(config.get("grouping", "sliding"))
    train_size = config.get("train_size", 0.8)

    if grouping == "sliding":
        split_mode = str(config.get("split_mode", "global"))
        split_suffix = "" if split_mode == "global" else f"_{split_mode}"
        chronological = _as_bool(config.get("is_chronological", False))
        run_name = (
            f"W{config['window_size']}_S{config['step_size']}_"
            f"C{chronological}_train{train_size}{split_suffix}"
        )
        return output_dir / dataset_name / "sliding" / run_name

    return output_dir / dataset_name / "session" / f"train{train_size}"


def resolve_cached_records_path(
    *,
    config_path: Path,
    records_name: str,
) -> Path:
    config = load_yaml_config(config_path)
    return compose_cached_run_dir(config, config_path=config_path) / records_name


def load_cached_records(records_path: Path) -> list[Any]:
    opener = gzip.open if records_path.suffix == ".gz" else open
    with opener(records_path, "rb") as handle:
        payload = pickle.load(handle)
    if not isinstance(payload, list):
        raise TypeError(f"Cached records must be a list, got {type(payload).__name__}")
    return payload


def _max_label(label: Any) -> int:
    if isinstance(label, (list, tuple)):
        if not label:
            return 0
        return int(max(_max_label(item) for item in label))
    return int(label)


def _record_sequence_and_label(record: Any) -> tuple[list[str], int]:
    if isinstance(record, dict):
        if "EventTemplate" not in record:
            raise KeyError("Cached record is missing EventTemplate")
        return [str(item) for item in record["EventTemplate"]], _max_label(record.get("Label", 0))
    if isinstance(record, (list, tuple)) and len(record) >= 2:
        sequence, label = record[0], record[1]
        return [str(item) for item in sequence], _max_label(label)
    raise TypeError(f"Unsupported cached record type: {type(record).__name__}")


def deduplicate_cached_sessions(records: Iterable[Any]) -> list[CachedSession]:
    label_by_sequence: dict[tuple[str, ...], int] = {}
    counts: Counter[tuple[str, ...]] = Counter()

    for record in records:
        sequence, label = _record_sequence_and_label(record)
        key = tuple(sequence)
        label_by_sequence[key] = label
        counts[key] += 1

    return [
        CachedSession(sequence=list(sequence), label=label, count=counts[sequence])
        for sequence, label in label_by_sequence.items()
    ]


def build_cached_windows(
    sessions: Sequence[CachedSession],
    *,
    history_size: int,
    pad_token: str,
) -> list[CachedWindow]:
    windows: list[CachedWindow] = []
    for session_idx, session in enumerate(sessions):
        line = list(session.sequence)
        pad_count = history_size - len(line) + 1
        if pad_count > 0:
            line.extend([pad_token] * pad_count)
        for offset in range(len(line) - history_size):
            windows.append(
                CachedWindow(
                    session_idx=session_idx,
                    window_idx=offset,
                    history=line[offset : offset + history_size],
                    target=line[offset + history_size],
                )
            )
    return windows


def expand_cached_predictions(
    *,
    sessions: Sequence[CachedSession],
    session_predictions: Sequence[int | bool],
    session_scores: Sequence[float] | None = None,
) -> tuple[list[int], list[int], list[float] | None]:
    y_true: list[int] = []
    y_pred: list[int] = []
    y_score: list[float] | None = [] if session_scores is not None else None

    for idx, session in enumerate(sessions):
        repeats = max(0, int(session.count))
        y_true.extend([int(session.label)] * repeats)
        y_pred.extend([int(bool(session_predictions[idx]))] * repeats)
        if y_score is not None and session_scores is not None:
            y_score.extend([float(session_scores[idx])] * repeats)

    return y_true, y_pred, y_score
