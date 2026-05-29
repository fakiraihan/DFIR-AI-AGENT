"""Summarize and compare EVTX corpus audit CSV files."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path
from typing import cast


NUMERIC_FIELDS = {
    "windows",
    "anomalies",
    "sequence_anomalies",
    "heuristic_anomalies",
    "unknown_windows",
}


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def as_int(row: dict[str, str], field: str) -> int:
    value = row.get(field, "0")
    try:
        return int(float(value or 0))
    except ValueError:
        return 0


def summarize(path: Path, rows: list[dict[str, str]]) -> None:
    print(f"\n## {path}")
    print(f"files: {len(rows)}")
    for field in NUMERIC_FIELDS:
        print(f"{field}: {sum(as_int(row, field) for row in rows)}")

    zero_rows = [row for row in rows if as_int(row, "anomalies") == 0]
    print(f"zero_anomaly_files: {len(zero_rows)}")

    profile_counts = Counter(row.get("profile", "") for row in rows)
    strategy_counts = Counter(row.get("template_strategy", "") for row in rows)
    zero_section_counts = Counter(row.get("section", "") for row in zero_rows)
    print(f"profiles: {dict(profile_counts.most_common())}")
    print(f"template_strategies: {dict(strategy_counts.most_common())}")
    print(f"top_zero_sections: {dict(zero_section_counts.most_common(12))}")


def compare(left_path: Path, left_rows: list[dict[str, str]], right_path: Path, right_rows: list[dict[str, str]]) -> None:
    left_by_path = {row.get("relative_path", ""): row for row in left_rows}
    right_by_path = {row.get("relative_path", ""): row for row in right_rows}
    common_paths = sorted(set(left_by_path) & set(right_by_path))

    zero_to_nonzero = 0
    nonzero_to_zero = 0
    right_more = 0
    right_fewer = 0
    same = 0

    for relative_path in common_paths:
        left_anomalies = as_int(left_by_path[relative_path], "anomalies")
        right_anomalies = as_int(right_by_path[relative_path], "anomalies")
        if left_anomalies == 0 and right_anomalies > 0:
            zero_to_nonzero += 1
        if left_anomalies > 0 and right_anomalies == 0:
            nonzero_to_zero += 1
        if right_anomalies > left_anomalies:
            right_more += 1
        elif right_anomalies < left_anomalies:
            right_fewer += 1
        else:
            same += 1

    print(f"\n## Compare: {left_path} -> {right_path}")
    print(f"common_files: {len(common_paths)}")
    print(f"zero_to_nonzero: {zero_to_nonzero}")
    print(f"nonzero_to_zero: {nonzero_to_zero}")
    print(f"right_more_anomalies: {right_more}")
    print(f"right_fewer_anomalies: {right_fewer}")
    print(f"same_anomaly_count: {same}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("csv_files", nargs="+", type=Path)
    args = parser.parse_args()
    csv_files = cast(list[Path], args.csv_files)

    loaded: list[tuple[Path, list[dict[str, str]]]] = []
    for csv_path in csv_files:
        rows = load_rows(csv_path)
        loaded.append((csv_path, rows))
        summarize(csv_path, rows)

    if len(loaded) >= 2:
        compare(loaded[0][0], loaded[0][1], loaded[1][0], loaded[1][1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
