"""
Prepare a DeepLog-compatible Sysmon dataset from fasttext-trainmodel.csv.

This source file is not raw log text. It contains per-event feature rows plus
`event.code` and `class`. For DeepLog we build a compact sequence dataset using
only the ordered Sysmon event codes.

Training output is normal-only to preserve DeepLog's unsupervised baseline.
An evaluation file with labels is also emitted for optional offline testing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pandas as pd


INPUT_CSV = Path(r"D:\FAKI\SYSMONMODEL\fasttext-trainmodel.csv")
OUTPUT_DIR = Path(__file__).resolve().parent / "SysmonFastText"
TRAIN_BASENAME = "sysmon_fasttext_normal"
EVAL_BASENAME = "sysmon_fasttext_eval"
EMBEDDING_DIM = 128
PROVIDER_NAME = "Microsoft-Windows-Sysmon"


def build_template(event_code: int) -> str:
    return f"{PROVIDER_NAME} EventID={int(event_code)}"


def build_structured_rows(df: pd.DataFrame, normal_only: bool) -> pd.DataFrame:
    working_df = df.copy()
    if normal_only:
        working_df = working_df[working_df["class"] == 0].copy()

    working_df = working_df.reset_index(drop=True)
    working_df["LineId"] = working_df.index + 1
    working_df["Timestamp"] = ""
    working_df["Label"] = working_df["class"].apply(
        lambda x: "-" if int(x) == 0 else "1"
    )
    working_df["EventId"] = working_df["event.code"].astype(int)
    working_df["EventTemplate"] = working_df["EventId"].apply(build_template)
    working_df["Content"] = working_df["EventTemplate"]

    return working_df[
        ["LineId", "Timestamp", "Label", "EventId", "EventTemplate", "Content"]
    ]


def write_template_metadata(df: pd.DataFrame, basename: str):
    template_counts = (
        df.groupby(["EventId", "EventTemplate"], dropna=False)
        .size()
        .reset_index(name="Occurrences")
    )
    template_counts.to_csv(OUTPUT_DIR / f"{basename}.log_templates.csv", index=False)


def write_zero_embeddings(df: pd.DataFrame):
    templates = sorted(df["EventTemplate"].dropna().unique().tolist())
    embeddings = {template: [0.0] * EMBEDDING_DIM for template in templates}
    with open(
        OUTPUT_DIR / "embeddings_average.json", "w", encoding="utf-8"
    ) as file_obj:
        json.dump(embeddings, file_obj)


def main():
    if not INPUT_CSV.exists():
        raise FileNotFoundError(f"Input CSV not found: {INPUT_CSV}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(INPUT_CSV)
    required_columns = {"event.code", "class"}
    missing = required_columns.difference(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    train_df = build_structured_rows(df, normal_only=True)
    eval_df = build_structured_rows(df, normal_only=False)

    train_path = OUTPUT_DIR / f"{TRAIN_BASENAME}_structured.csv"
    eval_path = OUTPUT_DIR / f"{EVAL_BASENAME}_structured.csv"
    train_df.to_csv(train_path, index=False)
    eval_df.to_csv(eval_path, index=False)

    write_template_metadata(train_df, TRAIN_BASENAME)
    write_template_metadata(eval_df, EVAL_BASENAME)
    write_zero_embeddings(train_df)

    normal_count = int((df["class"] == 0).sum())
    anomaly_count = int((df["class"] != 0).sum())

    print("=" * 70)
    print("Sysmon FastText Preprocessing for DeepLog")
    print("=" * 70)
    print(f"Input: {INPUT_CSV}")
    print(f"Train output: {train_path}")
    print(f"Eval output: {eval_path}")
    print(f"Normal events kept for training: {len(train_df):,}")
    print(f"Original normal events: {normal_count:,}")
    print(f"Original anomaly events: {anomaly_count:,}")
    print(f"Unique train templates: {train_df['EventTemplate'].nunique():,}")
    print("Template strategy for backend inference: provider_eventid")
    print("=" * 70)


if __name__ == "__main__":
    main()
