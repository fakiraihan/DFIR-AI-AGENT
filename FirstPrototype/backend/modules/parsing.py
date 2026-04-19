"""
Drain Log Parsing Module (Phase 1 focus).

Outputs per-line records that can be consumed by DeepLog and downstream DFIR steps.
"""

from __future__ import annotations

import json
import re
import tempfile
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import Evtx.Evtx as evtx
import pandas as pd
import xmltodict
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from tqdm import tqdm


def _resolve_training_workspace() -> Path:
    current = Path(__file__).resolve()
    repo_root = current.parents[3]  # D:\FAKI
    candidates = [
        repo_root / "NEWMLMODL",
        repo_root / "LogADEmpirical-dev",
    ]
    for candidate in candidates:
        if (candidate / "dataset" / "Drain.py").exists():
            return candidate
    raise FileNotFoundError("Unable to find training workspace with dataset/Drain.py")


class DrainParser:
    """Drain-based parser for EVTX and text logs."""

    def __init__(
        self,
        depth: int = 4,
        sim_threshold: float = 0.5,
        max_children: int = 100,
        template_strategy: str = "drain",
    ):
        self.depth = depth
        self.sim_threshold = sim_threshold
        self.max_children = max_children
        self.template_strategy = template_strategy

        config = TemplateMinerConfig()
        config.drain_depth = depth
        config.drain_sim_th = sim_threshold
        config.drain_max_children = max_children
        config.drain_max_clusters = 10000

        self.template_miner = TemplateMiner(config=config)
        self.latest_templates: List[Dict[str, Any]] = []
        self.training_workspace = _resolve_training_workspace()

    def preprocess_log_line(self, log_line: str) -> str:
        """Mask high-variance tokens before Drain parsing."""
        masked = log_line
        masked = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", masked)
        masked = re.sub(r"\b\d+\b", "<NUM>", masked)
        masked = re.sub(r"\b0x[0-9a-fA-F]+\b", "<HEX>", masked)
        masked = re.sub(r"[A-Za-z]:\\[\w\\.\-]+", "<PATH>", masked)
        masked = re.sub(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            "<UUID>",
            masked,
        )
        return masked

    def parse_evtx_file(
        self, file_path: str, max_lines: Optional[int] = None
    ) -> pd.DataFrame:
        """Parse Windows EVTX file and return per-line structured rows."""
        parsed_events: List[Dict] = []

        with evtx.Evtx(file_path) as log:
            for idx, record in enumerate(
                tqdm(log.records(), desc="Parsing EVTX"), start=1
            ):
                if max_lines is not None and idx > max_lines:
                    break
                try:
                    xml_content = record.xml()
                    event_dict = xmltodict.parse(xml_content)
                    event_data = event_dict.get("Event", {})

                    system = event_data.get("System", {})
                    event_id = system.get("EventID", {})
                    if isinstance(event_id, dict):
                        event_id = event_id.get("#text", "Unknown")

                    provider = system.get("Provider", {}).get("@Name", "Unknown")
                    timestamp = (
                        system.get("TimeCreated", {}).get("@SystemTime")
                        if isinstance(system.get("TimeCreated", {}), dict)
                        else None
                    )

                    raw_line = f"{provider} EventID={event_id}"
                    event_data_section = event_data.get("EventData", {})
                    data_items = (
                        event_data_section.get("Data", []) if event_data_section else []
                    )
                    if not isinstance(data_items, list):
                        data_items = [data_items]

                    for item in data_items:
                        if isinstance(item, dict):
                            key = item.get("@Name", "Unknown")
                            value = item.get("#text", "")
                            if value:
                                raw_line += f" {key}={value}"

                    event_template, cluster_id = self._build_evtx_template(
                        provider, event_id, raw_line
                    )

                    parameter_array, parameter_map = self._extract_parameters(raw_line)
                    parsed_events.append(
                        {
                            "line_number": idx,
                            "event_id": idx,
                            "timestamp": timestamp,
                            "event_template": event_template,
                            "parameter_array": parameter_array,
                            "parameter_map": parameter_map,
                            "parameters": json.dumps(parameter_array),
                            "raw_line": raw_line,
                            "cluster_id": cluster_id,
                        }
                    )
                except Exception:
                    continue

        dataframe = self._as_dataframe(parsed_events)
        self.latest_templates = self._derive_templates(dataframe)
        return dataframe

    def parse_csv_log(
        self, file_path: str, max_lines: Optional[int] = None
    ) -> pd.DataFrame:
        """Parse CSV logs, prioritizing Message/Content columns.

        Uses training-compatible Drain parser when available to reduce template mismatch.
        """
        nrows = max_lines if max_lines is not None else None
        dataframe = pd.read_csv(file_path, nrows=nrows)

        message_column = "Message" if "Message" in dataframe.columns else None
        if message_column is None and "Content" in dataframe.columns:
            message_column = "Content"

        timestamp_column = (
            "TimeGenerated" if "TimeGenerated" in dataframe.columns else None
        )
        if timestamp_column is None and "Timestamp" in dataframe.columns:
            timestamp_column = "Timestamp"

        if message_column is None:
            return self.parse_text_log(file_path, max_lines=max_lines)

        try:
            parsed_df, templates = self._parse_csv_with_training_drain(
                dataframe, message_column, timestamp_column
            )
            self.latest_templates = templates
            return parsed_df
        except Exception as exc:
            print(
                f"Training-compatible Drain parser unavailable, fallback to drain3: {exc}"
            )

        parsed_events: List[Dict] = []

        for idx, row in tqdm(
            dataframe.iterrows(), total=len(dataframe), desc="Parsing CSV logs"
        ):
            line_number = int(idx) + 1
            raw_line = (
                str(row.get(message_column, ""))
                .replace("\r", " ")
                .replace("\n", " ")
                .strip()
            )
            if not raw_line:
                continue

            timestamp = (
                str(row.get(timestamp_column, "")).strip() if timestamp_column else None
            )
            if timestamp == "nan":
                timestamp = None

            # Fallback parser path: avoid extra masking to stay closer to training data templates.
            result = self.template_miner.add_log_message(raw_line)
            parameter_array, parameter_map = self._extract_parameters(raw_line)

            parsed_events.append(
                {
                    "line_number": line_number,
                    "event_id": line_number,
                    "timestamp": timestamp,
                    "event_template": result["template_mined"],
                    "parameter_array": parameter_array,
                    "parameter_map": parameter_map,
                    "parameters": json.dumps(parameter_array),
                    "raw_line": raw_line,
                    "cluster_id": result["cluster_id"],
                }
            )

        dataframe = self._as_dataframe(parsed_events)
        self.latest_templates = self._derive_templates(dataframe)
        return dataframe

    def parse_text_log(
        self, file_path: str, max_lines: Optional[int] = None
    ) -> pd.DataFrame:
        """Parse text logs and return per-line structured rows."""
        parsed_events: List[Dict] = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as file_obj:
            for idx, line in enumerate(tqdm(file_obj, desc="Parsing logs"), start=1):
                if max_lines is not None and idx > max_lines:
                    break

                raw_line = line.strip()
                if not raw_line:
                    continue

                timestamp = self._extract_timestamp(raw_line)
                result = self.template_miner.add_log_message(raw_line)
                parameter_array, parameter_map = self._extract_parameters(raw_line)

                parsed_events.append(
                    {
                        "line_number": idx,
                        "event_id": idx,
                        "timestamp": timestamp,
                        "event_template": result["template_mined"],
                        "parameter_array": parameter_array,
                        "parameter_map": parameter_map,
                        "parameters": json.dumps(parameter_array),
                        "raw_line": raw_line,
                        "cluster_id": result["cluster_id"],
                    }
                )

        parsed_df = self._as_dataframe(parsed_events)
        self.latest_templates = self._derive_templates(parsed_df)
        return parsed_df

    def parse_file(
        self, file_path: str, max_lines: Optional[int] = None
    ) -> pd.DataFrame:
        """Auto-detect file type and parse."""
        path = Path(file_path)
        if path.suffix.lower() == ".evtx":
            return self.parse_evtx_file(file_path, max_lines=max_lines)
        if path.suffix.lower() == ".csv":
            return self.parse_csv_log(file_path, max_lines=max_lines)
        return self.parse_text_log(file_path, max_lines=max_lines)

    def get_templates(self) -> List[Dict]:
        """Return discovered Drain clusters."""
        if self.latest_templates:
            return self.latest_templates

        templates = []
        for cluster in self.template_miner.drain.clusters:
            templates.append(
                {
                    "cluster_id": cluster.cluster_id,
                    "template": str(cluster),
                    "size": cluster.size,
                }
            )
        return templates

    def _load_training_drain_module(self):
        drain_py = self.training_workspace / "dataset" / "Drain.py"
        module_name = "training_drain_module"
        spec = importlib.util.spec_from_file_location(module_name, str(drain_py))
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load Drain parser module from {drain_py}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _parse_csv_with_training_drain(
        self,
        dataframe: pd.DataFrame,
        message_column: str,
        timestamp_column: Optional[str],
    ) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
        drain_module = self._load_training_drain_module()
        parsed_events: List[Dict[str, Any]] = []

        with tempfile.TemporaryDirectory(prefix="dfir_training_drain_") as tmpdir:
            raw_log_filename = "eventlog.log"
            raw_log_path = Path(tmpdir) / raw_log_filename

            context_rows: List[Dict[str, Any]] = []
            with open(raw_log_path, "w", encoding="utf-8", newline="\n") as file_obj:
                for idx, row in dataframe.iterrows():
                    line_number = int(idx) + 1
                    raw_line = (
                        str(row.get(message_column, ""))
                        .replace("\r", " ")
                        .replace("\n", " ")
                        .strip()
                    )
                    if not raw_line:
                        continue

                    timestamp = (
                        str(row.get(timestamp_column, "")).strip()
                        if timestamp_column
                        else None
                    )
                    if timestamp == "nan":
                        timestamp = None

                    file_obj.write(raw_line + "\n")
                    context_rows.append(
                        {
                            "line_number": line_number,
                            "timestamp": timestamp,
                            "raw_line": raw_line,
                        }
                    )

            parser = drain_module.LogParser(
                "<Content>",
                indir=tmpdir,
                outdir=tmpdir,
                depth=self.depth,
                st=self.sim_threshold,
                maxChild=self.max_children,
            )
            parser.parse(raw_log_filename)

            structured_path = Path(tmpdir) / f"{raw_log_filename}_structured.csv"
            templates_path = Path(tmpdir) / f"{raw_log_filename}_templates.csv"
            structured_df = pd.read_csv(structured_path)

            row_count = min(len(context_rows), len(structured_df))
            for row_idx in range(row_count):
                structured_row = structured_df.iloc[row_idx]
                context = context_rows[row_idx]
                raw_line = context["raw_line"]

                parameter_array, parameter_map = self._extract_parameters(raw_line)
                parsed_events.append(
                    {
                        "line_number": context["line_number"],
                        "event_id": context["line_number"],
                        "timestamp": context["timestamp"],
                        "event_template": str(structured_row.get("EventTemplate", "")),
                        "parameter_array": parameter_array,
                        "parameter_map": parameter_map,
                        "parameters": json.dumps(parameter_array),
                        "raw_line": raw_line,
                        "cluster_id": str(structured_row.get("EventId", "")),
                    }
                )

            parsed_df = self._as_dataframe(parsed_events)

            templates: List[Dict[str, Any]] = []
            if templates_path.exists():
                template_df = pd.read_csv(templates_path)
                for _, row in template_df.iterrows():
                    templates.append(
                        {
                            "cluster_id": str(row.get("EventId", "")),
                            "template": str(row.get("EventTemplate", "")),
                            "size": int(row.get("Occurrences", 0)),
                        }
                    )

            if not templates:
                templates = self._derive_templates(parsed_df)

            return parsed_df, templates

    def _derive_templates(self, dataframe: pd.DataFrame) -> List[Dict[str, Any]]:
        if dataframe.empty:
            return []

        grouped = (
            dataframe.groupby(["cluster_id", "event_template"], dropna=False)
            .size()
            .reset_index(name="size")
        )
        templates: List[Dict[str, Any]] = []
        for _, row in grouped.iterrows():
            templates.append(
                {
                    "cluster_id": row.get("cluster_id"),
                    "template": str(row.get("event_template", "")),
                    "size": int(row.get("size", 0)),
                }
            )
        return templates

    def _build_evtx_template(
        self, provider: str, event_id: Any, raw_line: str
    ) -> Tuple[str, Any]:
        if self.template_strategy == "provider_eventid":
            template = f"{provider} EventID={event_id}"
            return template, template

        result = self.template_miner.add_log_message(raw_line)
        return result["template_mined"], result["cluster_id"]

    def _extract_parameters(self, original: str) -> Tuple[List[str], Dict[str, str]]:
        """Extract IOC-relevant values and structured key-value mapping."""
        parameter_map: Dict[str, str] = {}

        # key=value capture first (keeps original context for DFIR traceability)
        key_value_pattern = re.compile(
            r"\b([A-Za-z_][\w.-]{0,63})=(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
        )
        for match in key_value_pattern.finditer(original):
            key = match.group(1)
            value = match.group(2).strip().strip('"').strip("'")
            if value:
                self._insert_parameter(parameter_map, key, value)

        # IOC patterns
        for idx, value in enumerate(
            re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", original), start=1
        ):
            self._insert_parameter(parameter_map, f"ip_{idx}", value)

        for idx, value in enumerate(
            re.findall(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b", original), start=1
        ):
            self._insert_parameter(parameter_map, f"hash_{idx}", value)

        for idx, value in enumerate(
            re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", original), start=1
        ):
            self._insert_parameter(parameter_map, f"domain_{idx}", value)

        for idx, value in enumerate(re.findall(r"https?://[^\s]+", original), start=1):
            self._insert_parameter(parameter_map, f"url_{idx}", value)

        # parameter_array stays as value-only list for compatibility with existing IOC extraction
        parameter_array = self._dedupe_preserve_order(list(parameter_map.values()))
        return parameter_array, parameter_map

    def _insert_parameter(self, target: Dict[str, str], key: str, value: str):
        if key not in target:
            target[key] = value
            return

        suffix = 2
        while f"{key}_{suffix}" in target:
            suffix += 1
        target[f"{key}_{suffix}"] = value

    def _dedupe_preserve_order(self, values: List[str]) -> List[str]:
        result: List[str] = []
        seen = set()
        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _extract_timestamp(self, line: str) -> Optional[str]:
        """Best-effort timestamp extraction for text logs."""
        patterns = [
            r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
            r"\b\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2}\b",
            r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(0)
        return None

    def _as_dataframe(self, parsed_events: List[Dict]) -> pd.DataFrame:
        columns = [
            "line_number",
            "event_id",
            "timestamp",
            "event_template",
            "parameter_array",
            "parameter_map",
            "parameters",
            "raw_line",
            "cluster_id",
        ]
        if not parsed_events:
            return pd.DataFrame(columns=columns)

        df = pd.DataFrame(parsed_events)
        for col in columns:
            if col not in df.columns:
                df[col] = None
        return df[columns]


def parse_log_file(file_path: str, **kwargs) -> Tuple[pd.DataFrame, List[Dict]]:
    """Convenience parser entrypoint."""
    max_lines = kwargs.pop("max_lines", None)
    parser = DrainParser(**kwargs)
    df = parser.parse_file(file_path, max_lines=max_lines)
    templates = parser.get_templates()
    return df, templates
