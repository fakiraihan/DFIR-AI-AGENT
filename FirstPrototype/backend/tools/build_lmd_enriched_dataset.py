"""Build an LMD-2023 structured CSV with enriched DeepLog templates."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.deeplog_template_enrichment import (  # noqa: E402
    ENRICHMENT_LMD_SYSMON_V1,
    enrich_structured_dataframe,
)


DEFAULT_INPUT = Path(
    r"D:\FAKI\NEWMLMODL\dataset\lmd2023_2_3m\lmd2023.log_structured.csv"
)
DEFAULT_OUTPUT = Path(
    r"D:\FAKI\NEWMLMODL\dataset\lmd2023_2_3m_enriched\lmd2023.log_structured.csv"
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


def _label_counts(df: pd.DataFrame) -> dict[str, int]:
    if "Label" not in df.columns:
        return {}
    return {str(k): int(v) for k, v in df["Label"].value_counts(dropna=False).to_dict().items()}


def _event_id_counts(df: pd.DataFrame) -> dict[str, int]:
    column = "EventID" if "EventID" in df.columns else "EventId" if "EventId" in df.columns else ""
    if not column:
        return {}
    counts = Counter()
    for value, count in df[column].value_counts(dropna=False).to_dict().items():
        try:
            key = str(int(float(value)))
        except (TypeError, ValueError):
            key = str(value)
        counts[key] += int(count)
    return dict(counts.most_common())


def build_enriched_dataset(
    *,
    input_path: Path,
    output_path: Path,
    mode: str = ENRICHMENT_LMD_SYSMON_V1,
    chunksize: int = 100_000,
    max_lines: int | None = None,
    summary_path: Path | None = None,
) -> dict[str, Any]:
    """Build a chunked enriched CSV and return a small summary."""
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input structured CSV not found: {input_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    rows = 0
    chunks = 0
    label_counts: Counter[str] = Counter()
    event_id_counts: Counter[str] = Counter()
    template_counts: Counter[str] = Counter()

    reader = pd.read_csv(
        input_path,
        chunksize=chunksize,
        nrows=max_lines,
        low_memory=False,
    )
    for chunk in reader:
        enriched = enrich_structured_dataframe(chunk, mode=mode)
        enriched.to_csv(
            output_path,
            index=False,
            mode="w" if chunks == 0 else "a",
            header=chunks == 0,
        )
        rows += len(enriched)
        chunks += 1
        label_counts.update(_label_counts(enriched))
        event_id_counts.update(_event_id_counts(enriched))
        if "EventTemplate" in enriched.columns:
            template_counts.update(
                {
                    str(key): int(value)
                    for key, value in enriched["EventTemplate"]
                    .value_counts(dropna=False)
                    .to_dict()
                    .items()
                }
            )

    summary = {
        "input_path": input_path,
        "output_path": output_path,
        "mode": mode,
        "rows": rows,
        "chunks": chunks,
        "max_lines": max_lines,
        "label_counts": dict(label_counts.most_common()),
        "event_id_counts": dict(event_id_counts.most_common()),
        "unique_event_templates": len(template_counts),
        "top_event_templates": dict(template_counts.most_common(25)),
    }
    if summary_path is None:
        summary_path = output_path.with_suffix(".summary.json")
    _write_json(Path(summary_path), summary)
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build LMD-2023 enriched structured CSV for DeepLog retraining."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--mode", default=ENRICHMENT_LMD_SYSMON_V1)
    parser.add_argument("--chunksize", type=int, default=100_000)
    parser.add_argument("--max-lines", type=int, default=None)
    parser.add_argument("--summary", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = build_enriched_dataset(
        input_path=args.input,
        output_path=args.output,
        mode=args.mode,
        chunksize=args.chunksize,
        max_lines=args.max_lines,
        summary_path=args.summary,
    )
    print(json.dumps(summary, indent=2, sort_keys=True, default=_json_default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
