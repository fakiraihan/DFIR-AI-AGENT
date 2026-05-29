"""
DeepLog anomaly detection module (Phase 1 focus).

Provides per-window and per-line anomaly outputs for downstream DFIR pipeline.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

import pandas as pd
import torch
from tqdm import tqdm

from modules.anomaly_decision import (
    apply_decision_policy,
    candidate_metadata,
    resolve_decision_policy,
)
from logadempirical.data.vocab import Vocab
from logadempirical.models.lstm import DeepLog as DeepLogModel


class DeepLogDetector:
    """DeepLog inference with enriched anomaly output schema."""

    def __init__(
        self,
        model_path: str,
        vocab_path: str,
        window_size: int = 20,
        step_size: int = 1,
        topk: int = 9,
        device: str = "cpu",
        skip_unknown_windows: bool = True,
        max_unknown_ratio: float = 0.4,
        unknown_template_mode: str | None = None,
        evtx_sparse_fallback_enabled: bool = True,
        evtx_sparse_fallback_threshold: float = 0.75,
        template_similarity_enabled: bool = False,
        template_similarity_threshold: float = 0.65,
        use_bos_context: bool = False,
        bos_token: str = "<BOS>",
        bos_count: int | None = None,
        decision_policy: str = "topk",
        score_threshold: float | None = None,
        medium_score_threshold: float = 0.70,
        recall_floor: float = 0.80,
    ):
        self.window_size = window_size
        self.step_size = step_size
        self.topk = topk
        self.device = device
        self.skip_unknown_windows = skip_unknown_windows
        self.max_unknown_ratio = max_unknown_ratio
        self.unknown_template_mode = self._resolve_unknown_template_mode(
            unknown_template_mode, skip_unknown_windows
        )
        self.evtx_sparse_fallback_enabled = evtx_sparse_fallback_enabled
        self.evtx_sparse_fallback_threshold = evtx_sparse_fallback_threshold
        self.template_similarity_enabled = template_similarity_enabled
        self.template_similarity_threshold = template_similarity_threshold
        self.use_bos_context = use_bos_context
        self.bos_token = bos_token
        self.bos_count = int(bos_count if bos_count is not None else window_size)
        self.decision_policy = resolve_decision_policy(decision_policy)
        self.score_threshold = (
            float(score_threshold) if score_threshold is not None else None
        )
        self.medium_score_threshold = float(medium_score_threshold)
        self.recall_floor = float(recall_floor)
        self._template_similarity_cache: Dict[str, int] = {}
        self._template_similarity_candidates: List[Tuple[int, set[str]]] | None = None

        self.vocab = Vocab.load_vocab(vocab_path)
        self.unk_index = getattr(self.vocab, "unk_index", None)
        checkpoint = torch.load(model_path, map_location=device)
        model_state = (
            checkpoint["model"]
            if isinstance(checkpoint, dict) and "model" in checkpoint
            else checkpoint
        )

        model_cfg = self._infer_model_config(model_state, len(self.vocab))
        self.model = DeepLogModel(
            vocab_size=model_cfg["vocab_size"],
            embedding_dim=model_cfg["embedding_dim"],
            hidden_size=model_cfg["hidden_size"],
            num_layers=model_cfg["num_layers"],
            dropout=model_cfg["dropout"],
            criterion=None,
        )
        self.model.load_state_dict(model_state)
        self.model.to(device)
        self.model.eval()

    def _infer_model_config(
        self, model_state: Dict[str, torch.Tensor], fallback_vocab_size: int
    ) -> Dict[str, Any]:
        embedding_weight = model_state.get("embedding.weight")
        fc_weight = model_state.get("fc.weight")
        lstm_hh = model_state.get("lstm.weight_hh_l0")

        embedding_dim = (
            int(embedding_weight.shape[1]) if embedding_weight is not None else 128
        )
        hidden_size = int(lstm_hh.shape[1]) if lstm_hh is not None else 128
        vocab_size = (
            int(fc_weight.shape[0]) if fc_weight is not None else fallback_vocab_size
        )

        num_layers = 0
        for key in model_state.keys():
            match = re.match(r"lstm\.weight_ih_l(\d+)", key)
            if match:
                num_layers = max(num_layers, int(match.group(1)) + 1)
        if num_layers == 0:
            num_layers = 2

        return {
            "embedding_dim": embedding_dim,
            "hidden_size": hidden_size,
            "vocab_size": vocab_size,
            "num_layers": num_layers,
            "dropout": 0.1,
        }

    def detect_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return self._empty_results()

        if len(df) <= self.window_size and getattr(
            self, "evtx_sparse_fallback_enabled", True
        ):
            fallback_results = self._detect_sparse_evtx_fallback(df)
            if not fallback_results.empty:
                return fallback_results

        if len(df) <= 1 and not getattr(self, "use_bos_context", False):
            return self._empty_results()

        effective_df = self._prepend_bos_context(df)
        templates = effective_df["event_template"].astype(str).tolist()
        history_size = min(self.window_size, max(1, len(templates) - 1))
        windows = self._build_windows(len(templates), history_size=history_size)
        results: List[Dict[str, Any]] = []

        for window_id, start_idx, next_idx in tqdm(windows, desc="Detecting anomalies"):
            window_templates = templates[start_idx:next_idx]
            actual_event = templates[next_idx]

            window_indices = [
                self._event_to_index(template) for template in window_templates
            ]
            actual_idx = self._event_to_index(actual_event)

            topk_indices, topk_probs, actual_prob = self._predict_topk(
                window_indices, actual_idx
            )

            unknown_count = self._count_unknown_tokens(window_indices, actual_idx)
            unknown_ratio = float(unknown_count / (len(window_indices) + 1))
            unknown_reason = self._unknown_template_reason(actual_idx, unknown_ratio)
            fallback_score, fallback_reasons = self._fallback_for_unknown_evtx_row(
                effective_df.iloc[next_idx], unknown_reason
            )

            evaluation_status = "evaluated"
            strict_is_anomaly = actual_idx not in topk_indices
            if fallback_reasons and fallback_score >= getattr(
                self, "evtx_sparse_fallback_threshold", 0.75
            ):
                evaluation_status = "evtx_heuristic_boost"
                is_anomaly = True
                strict_is_anomaly = False
                anomaly_score = fallback_score
            elif unknown_reason and self.unknown_template_mode == "ignore":
                evaluation_status = unknown_reason
                is_anomaly = False
                strict_is_anomaly = False
                anomaly_score = 0.0
            elif unknown_reason and self.unknown_template_mode == "warn":
                evaluation_status = unknown_reason
                is_anomaly = False
                strict_is_anomaly = False
                anomaly_score = float(max(0.0, 1.0 - actual_prob))
            elif unknown_reason and self.unknown_template_mode == "anomaly":
                evaluation_status = unknown_reason
                is_anomaly = True
                anomaly_score = 1.0
            else:
                is_anomaly = strict_is_anomaly
                anomaly_score = float(max(0.0, 1.0 - actual_prob))
                if is_anomaly:
                    evaluation_status = "deeplog_topk_miss"

            is_anomaly, evaluation_status = apply_decision_policy(
                decision_policy=getattr(self, "decision_policy", "topk"),
                is_anomaly=is_anomaly,
                strict_is_anomaly=strict_is_anomaly,
                anomaly_score=anomaly_score,
                evaluation_status=evaluation_status,
                score_threshold=getattr(self, "score_threshold", None),
            )
            candidate_tier, candidate_reasons = candidate_metadata(
                is_anomaly=is_anomaly,
                strict_is_anomaly=strict_is_anomaly,
                anomaly_score=anomaly_score,
                evaluation_status=evaluation_status,
                medium_score_threshold=getattr(self, "medium_score_threshold", 0.70),
                fallback_reasons=fallback_reasons,
                unknown_reason=unknown_reason,
            )

            predicted_events = [self._index_to_event(idx) for idx in topk_indices]
            line_payload = self._build_line_payload(
                effective_df,
                start_idx,
                next_idx,
                is_anomaly,
            )
            anomalous_line = line_payload[-1] if line_payload else {}
            window_key_indicators = self._collect_window_indicators(line_payload)

            results.append(
                {
                    "window_id": window_id,
                    "start_idx": start_idx,
                    "end_idx": next_idx,
                    "is_anomaly": is_anomaly,
                    "strict_is_anomaly": strict_is_anomaly,
                    "candidate_tier": candidate_tier,
                    "candidate_reasons": candidate_reasons,
                    "decision_policy": getattr(self, "decision_policy", "topk"),
                    "score_threshold": getattr(self, "score_threshold", None),
                    "recall_floor": getattr(self, "recall_floor", None),
                    "anomaly_score": anomaly_score,
                    "evaluation_status": evaluation_status,
                    "unknown_ratio": unknown_ratio,
                    "unknown_count": unknown_count,
                    "lines": line_payload,
                    "predicted_event": predicted_events[0]
                    if predicted_events
                    else "unknown",
                    "actual_event": actual_event,
                    "actual_event_index": actual_idx,
                    "actual_probability": actual_prob,
                    "topk_indices": "|".join(str(idx) for idx in topk_indices),
                    "predicted_events": "|".join(predicted_events),
                    "expected_events": "|".join(predicted_events),
                    "window_templates": " | ".join(window_templates),
                    "topk_probabilities": topk_probs,
                    "anomalous_line": anomalous_line,
                    "window_key_indicators": window_key_indicators,
                    "fallback_reasons": fallback_reasons,
                }
            )

        return pd.DataFrame(results)

    def _prepend_bos_context(self, df: pd.DataFrame) -> pd.DataFrame:
        if not getattr(self, "use_bos_context", False):
            return df.reset_index(drop=True)

        bos_count = max(0, int(getattr(self, "bos_count", 0)))
        if bos_count == 0:
            return df.reset_index(drop=True)

        original_df = df.copy().reset_index(drop=True)
        original_df["is_virtual_context"] = False
        bos_rows = []
        for offset in range(bos_count):
            row = {column: "" for column in original_df.columns}
            row["event_template"] = self.bos_token
            if "EventTemplate" in row:
                row["EventTemplate"] = self.bos_token
            if "Content" in row:
                row["Content"] = self.bos_token
            if "raw_line" in row:
                row["raw_line"] = self.bos_token
            if "line_number" in row:
                row["line_number"] = 0
            if "event_id" in row:
                row["event_id"] = 0
            if "EventId" in row:
                row["EventId"] = 0
            row["is_virtual_context"] = True
            row["virtual_context_index"] = offset + 1
            bos_rows.append(row)

        return pd.concat([pd.DataFrame(bos_rows), original_df], ignore_index=True)

    def _empty_results(self) -> pd.DataFrame:
        return pd.DataFrame(
            columns=[
                "window_id",
                "start_idx",
                "end_idx",
                "is_anomaly",
                "strict_is_anomaly",
                "candidate_tier",
                "candidate_reasons",
                "decision_policy",
                "score_threshold",
                "recall_floor",
                "anomaly_score",
                "evaluation_status",
                "unknown_ratio",
                "unknown_count",
                "lines",
                "predicted_event",
                "actual_event",
                "actual_event_index",
                "actual_probability",
                "topk_indices",
                "predicted_events",
                "expected_events",
                "window_templates",
            ]
        )

    def _detect_sparse_evtx_fallback(self, df: pd.DataFrame) -> pd.DataFrame:
        if not getattr(self, "evtx_sparse_fallback_enabled", True):
            return self._empty_results()

        results: List[Dict[str, Any]] = []
        for row_index in range(len(df)):
            row = df.iloc[row_index]
            if not self._is_evtx_like_row(row):
                continue

            score, reasons = self._score_sparse_evtx_row(row)
            is_anomaly = score >= getattr(
                self, "evtx_sparse_fallback_threshold", 0.75
            )
            candidate_tier, candidate_reasons = candidate_metadata(
                is_anomaly=is_anomaly,
                strict_is_anomaly=False,
                anomaly_score=score,
                evaluation_status="evtx_sparse_fallback",
                medium_score_threshold=getattr(self, "medium_score_threshold", 0.70),
                fallback_reasons=reasons,
                unknown_reason="",
            )
            line_payload = self._build_line_payload(df, row_index, row_index, is_anomaly)
            anomalous_line = line_payload[-1] if line_payload else {}
            window_key_indicators = self._collect_window_indicators(line_payload)
            actual_event = str(
                row.get("event_template")
                or row.get("EventTemplate")
                or row.get("raw_line")
                or ""
            )

            results.append(
                {
                    "window_id": len(results),
                    "start_idx": row_index,
                    "end_idx": row_index,
                    "is_anomaly": is_anomaly,
                    "strict_is_anomaly": False,
                    "candidate_tier": candidate_tier,
                    "candidate_reasons": candidate_reasons,
                    "decision_policy": getattr(self, "decision_policy", "topk"),
                    "score_threshold": getattr(self, "score_threshold", None),
                    "recall_floor": getattr(self, "recall_floor", None),
                    "anomaly_score": score,
                    "evaluation_status": "evtx_sparse_fallback",
                    "unknown_ratio": 1.0,
                    "unknown_count": 1,
                    "lines": line_payload,
                    "predicted_event": "evtx_sparse_fallback",
                    "actual_event": actual_event,
                    "actual_event_index": -1,
                    "actual_probability": 0.0,
                    "topk_indices": "",
                    "predicted_events": "",
                    "expected_events": "",
                    "window_templates": actual_event,
                    "topk_probabilities": [],
                    "anomalous_line": anomalous_line,
                    "window_key_indicators": window_key_indicators,
                    "fallback_reasons": reasons,
                }
            )

        if not results:
            return self._empty_results()
        return pd.DataFrame(results)

    def _is_evtx_like_row(self, row: pd.Series) -> bool:
        event_id = row.get("EventId", row.get("event_id", ""))
        provider = row.get("Component", row.get("Provider", row.get("provider", "")))
        template = row.get("EventTemplate", row.get("event_template", ""))
        raw_line = row.get("raw_line", row.get("Content", ""))

        if event_id not in (None, ""):
            return True
        if provider and template:
            return True
        return bool(re.search(r"\bEventID=\d+\b", str(template or raw_line)))

    def _score_sparse_evtx_row(self, row: pd.Series) -> Tuple[float, List[str]]:
        parameter_map = self._safe_load_parameter_map(row)
        if not parameter_map:
            parameter_map = self._parameter_map(self._safe_load_parameters(row))

        event_id = self._extract_row_event_id(row, parameter_map)
        level = str(row.get("Level", row.get("level", ""))).lower()
        text_parts = [
            str(row.get("Component", "")),
            str(row.get("Provider", "")),
            str(row.get("EventTemplate", "")),
            str(row.get("event_template", "")),
            str(row.get("Content", "")),
            str(row.get("ParameterList", "")),
            str(row.get("raw_line", "")),
            " ".join(str(value) for value in parameter_map.values()),
        ]
        text = " ".join(part for part in text_parts if part).lower()
        important_fields = self._collect_important_fields(parameter_map)

        score = 0.0
        reasons: List[str] = []
        suspicious_terms = {
            "encodedcommand": 0.45,
            " -enc ": 0.45,
            "invoke-mimikatz": 0.5,
            "mimikatz": 0.5,
            "lsass": 0.35,
            "sekurlsa": 0.5,
            "rundll32": 0.3,
            "regsvr32": 0.35,
            "certutil": 0.35,
            "wmic": 0.25,
            "powershell": 0.3,
            "downloadstring": 0.45,
            "frombase64string": 0.45,
            "schtasks": 0.25,
            "\\temp\\": 0.2,
        }
        for term, weight in suspicious_terms.items():
            if term in text:
                score += weight
                reasons.append(f"term:{term.strip()}")

        if event_id in {"1", "3", "7", "8", "10", "11", "13", "22", "4698", "7045"}:
            score += 0.2
            reasons.append(f"event_id:{event_id}")

        if level in {"critical", "error", "warning", "warn"}:
            score += 0.1
            reasons.append(f"level:{level}")

        if important_fields.get("command_line") and any(
            token in important_fields["command_line"].lower()
            for token in ["-enc", "encodedcommand", "downloadstring", "frombase64string"]
        ):
            score += 0.25
            reasons.append("field:command_line")

        if important_fields.get("target_object") and "\\temp\\" in important_fields[
            "target_object"
        ].lower():
            score += 0.1
            reasons.append("field:target_object")

        return min(score, 1.0), reasons

    def _fallback_for_unknown_evtx_row(
        self, row: pd.Series, unknown_reason: str
    ) -> Tuple[float, List[str]]:
        if not unknown_reason:
            return 0.0, []
        if not getattr(self, "evtx_sparse_fallback_enabled", True):
            return 0.0, []
        if not self._is_evtx_like_row(row):
            return 0.0, []
        return self._score_sparse_evtx_row(row)

    def _extract_row_event_id(
        self, row: pd.Series, parameter_map: Dict[str, str] | None = None
    ) -> str:
        parameter_map = parameter_map or {}
        text_parts = [
            str(row.get("EventTemplate", "")),
            str(row.get("event_template", "")),
            str(row.get("Content", "")),
            str(row.get("raw_line", "")),
            " ".join(str(value) for value in parameter_map.values()),
        ]
        text = " ".join(part for part in text_parts if part)
        match = re.search(r"\bEventID=(?P<event_id>\d+)\b", text)
        if match:
            return match.group("event_id")

        for key in ("EventID", "EventId", "event_code"):
            value = row.get(key)
            if value not in (None, ""):
                return str(value).strip()

        for key, value in parameter_map.items():
            if self._normalize_key(str(key)) == "eventid" and value:
                return str(value).strip()

        return ""

    def _count_unknown_tokens(self, window_indices: List[int], actual_idx: int) -> int:
        if self.unk_index is None:
            return 0
        count = sum(1 for idx in window_indices if idx == self.unk_index)
        if actual_idx == self.unk_index:
            count += 1
        return count

    def _resolve_unknown_template_mode(
        self, unknown_template_mode: str | None, skip_unknown_windows: bool
    ) -> str:
        if unknown_template_mode is None:
            return "ignore" if skip_unknown_windows else "warn"
        mode = str(unknown_template_mode).strip().lower()
        if mode not in {"ignore", "warn", "anomaly", "evaluate"}:
            raise ValueError(
                "unknown_template_mode must be one of: ignore, warn, anomaly, evaluate"
            )
        return mode

    def _unknown_template_reason(self, actual_idx: int, unknown_ratio: float) -> str:
        if self.unk_index is None:
            return ""
        if actual_idx == self.unk_index:
            return "unknown_template"
        # Guardrail to avoid false flood when parser-template mismatch is high.
        if unknown_ratio >= self.max_unknown_ratio:
            return "unknown_template_ratio_exceeded"
        return ""

    def get_anomalous_windows(self, results_df: pd.DataFrame) -> pd.DataFrame:
        return results_df[results_df["is_anomaly"] == True].copy()

    def _build_windows(
        self, total_templates: int, history_size: int | None = None
    ) -> List[Tuple[int, int, int]]:
        windows: List[Tuple[int, int, int]] = []
        window_id = 0
        effective_window_size = history_size or self.window_size
        for start_idx in range(0, total_templates - effective_window_size, self.step_size):
            next_idx = start_idx + effective_window_size
            if next_idx < total_templates:
                windows.append((window_id, start_idx, next_idx))
                window_id += 1
        return windows

    def _predict_topk(
        self, window_indices: List[int], actual_idx: int
    ) -> Tuple[List[int], List[float], float]:
        with torch.no_grad():
            x = torch.tensor([window_indices], dtype=torch.long).to(self.device)
            batch = {"sequential": x}
            output = self.model(batch, device=self.device)
            logits = output.logits[0]
            probabilities = torch.softmax(logits, dim=-1)

            topk_probs, topk_indices = torch.topk(probabilities, self.topk)
            topk_idx_list = topk_indices.cpu().numpy().tolist()
            topk_prob_list = [float(v) for v in topk_probs.cpu().numpy().tolist()]

            if 0 <= actual_idx < probabilities.shape[0]:
                actual_prob = float(probabilities[actual_idx].item())
            else:
                actual_prob = 0.0

            return topk_idx_list, topk_prob_list, actual_prob

    def _build_line_payload(
        self,
        df: pd.DataFrame,
        start_idx: int,
        next_idx: int,
        is_anomaly: bool,
    ) -> List[Dict[str, Any]]:
        lines: List[Dict[str, Any]] = []
        end_inclusive = min(next_idx, len(df) - 1)
        for row_index in range(start_idx, end_inclusive + 1):
            row = df.iloc[row_index]
            if bool(row.get("is_virtual_context", False)):
                continue
            parameter_map = self._safe_load_parameter_map(row)
            if not parameter_map:
                parameter_values = self._safe_load_parameters(row)
                parameter_map = self._parameter_map(parameter_values)
            important_fields = self._collect_important_fields(parameter_map)
            lines.append(
                {
                    "line_number": int(
                        row.get("line_number", row.get("event_id", row_index + 1))
                    ),
                    "timestamp": str(row.get("timestamp") or ""),
                    "event_template": str(row.get("event_template", "")),
                    "parameters": parameter_map,
                    "important_fields": important_fields,
                    "event_identity": self._extract_event_identity(
                        str(row.get("event_template", "")),
                        str(row.get("raw_line", "")),
                    ),
                    "raw_line": str(row.get("raw_line", "")),
                    "line_summary": self._build_line_summary(
                        str(row.get("event_template", "")),
                        important_fields,
                    ),
                    "is_anomalous_line": bool(is_anomaly and row_index == next_idx),
                }
            )
        return lines

    def _collect_window_indicators(
        self, lines: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        indicator_keys = [
            "image",
            "command_line",
            "parent_image",
            "target_object",
            "destination_ip",
            "destination_port",
            "source_ip",
            "source_port",
            "query_name",
            "object_name",
            "object_type",
            "relative_target_name",
            "share_name",
            "access_mask",
            "url",
            "domain",
            "hashes",
            "user",
        ]
        indicators: Dict[str, List[str]] = {}

        for key in indicator_keys:
            seen = set()
            values: List[str] = []
            for line in lines:
                fields = line.get("important_fields") or {}
                value = fields.get(key)
                if not value:
                    continue
                value_str = str(value)
                if value_str in seen:
                    continue
                seen.add(value_str)
                values.append(value_str)
                if len(values) >= 5:
                    break
            if values:
                indicators[key] = values

        return indicators

    def _collect_important_fields(
        self, parameter_map: Dict[str, str]
    ) -> Dict[str, str]:
        field_aliases = {
            "image": ["image", "targetimage", "sourceimage", "newprocessname"],
            "command_line": ["commandline", "details", "parentcommandline"],
            "parent_image": ["parentimage"],
            "image_loaded": ["imageloaded", "loadedimage"],
            "signature": ["signed", "signature"],
            "signature_status": ["signaturestatus"],
            "target_object": ["targetobject", "targetfilename", "imagepath"],
            "object_name": ["objectname"],
            "object_type": ["objecttype"],
            "relative_target_name": ["relativetargetname"],
            "share_name": ["sharename"],
            "access_mask": ["accessmask"],
            "user": ["user", "targetuser", "parentuser", "subjectusername"],
            "subject_user": ["subjectusername"],
            "target_user": ["targetusername", "accountname"],
            "process_name": ["processname"],
            "hashes": ["hashes", "hash", "sha256", "md5"],
            "destination_ip": ["destinationip", "destip", "ip"],
            "destination_port": ["destinationport", "destport", "port"],
            "source_ip": ["sourceip"],
            "source_port": ["sourceport"],
            "process_guid": ["processguid", "targetprocessguid", "sourceprocessguid"],
            "process_id": ["processid", "targetprocessid", "sourceprocessid"],
            "parent_process_id": ["parentprocessid"],
            "query_name": ["queryname"],
            "query_results": ["queryresults"],
            "granted_access": ["grantedaccess"],
            "call_trace": ["calltrace"],
            "protocol": ["protocol"],
            "domain": ["domain", "domain1"],
            "url": ["url", "url1"],
        }

        details: Dict[str, str] = {}
        for output_key, aliases in field_aliases.items():
            value = self._find_parameter_value(parameter_map, aliases)
            if value:
                details[output_key] = value

        return details

    def _extract_event_identity(
        self, event_template: str, raw_line: str
    ) -> Dict[str, str]:
        source = event_template or raw_line
        match = re.search(r"^(?P<provider>.+?)\s+EventID=(?P<event_id>\d+)", source)
        if not match:
            return {"provider": "", "event_id": ""}
        return {
            "provider": match.group("provider").strip(),
            "event_id": match.group("event_id").strip(),
        }

    def _build_line_summary(self, event_template: str, fields: Dict[str, str]) -> str:
        if not fields:
            return event_template

        ordered_keys = [
            "image",
            "command_line",
            "parent_image",
            "target_object",
            "destination_ip",
            "destination_port",
            "query_name",
            "user",
        ]
        snippets: List[str] = []
        for key in ordered_keys:
            value = fields.get(key)
            if not value:
                continue
            snippets.append(f"{key}={value}")
            if len(snippets) >= 4:
                break

        if not snippets:
            return event_template
        return f"{event_template} | " + " | ".join(snippets)

    def _find_parameter_value(
        self, parameter_map: Dict[str, str], candidate_keys: List[str]
    ) -> str:
        if not parameter_map:
            return ""

        normalized_candidates = [self._normalize_key(key) for key in candidate_keys]
        for key, value in parameter_map.items():
            normalized_key = self._normalize_key(str(key))
            for candidate in normalized_candidates:
                if normalized_key == candidate or normalized_key.startswith(candidate):
                    if value:
                        return str(value)
        return ""

    def _normalize_key(self, value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.lower())

    def _safe_load_parameter_map(self, row: pd.Series) -> Dict[str, str]:
        value = row.get("parameter_map", {})
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        if isinstance(value, str) and value:
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return {str(k): str(v) for k, v in parsed.items()}
            except Exception:
                return {}
        return {}

    def _safe_load_parameters(self, row: pd.Series) -> List[str]:
        value = row.get("parameters", "[]")
        if isinstance(value, list):
            return [str(v) for v in value]
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(v) for v in parsed]
        except Exception:
            pass
        return []

    def _parameter_map(self, parameter_values: List[str]) -> Dict[str, str]:
        mapped: Dict[str, str] = {}
        for idx, value in enumerate(parameter_values, start=1):
            key = f"value_{idx}"
            mapped[key] = value
            if self._is_ipv4(value) and "ip" not in mapped:
                mapped["ip"] = value
            elif value.startswith(("http://", "https://")) and "url" not in mapped:
                mapped["url"] = value
            elif self._is_hash(value) and "hash" not in mapped:
                mapped["hash"] = value
            elif self._is_domain(value) and "domain" not in mapped:
                mapped["domain"] = value
        return mapped

    def _template_tokens(self, value: str) -> set[str]:
        placeholder_tokens = {
            "num",
            "ip",
            "ipport",
            "path",
            "regpath",
            "guid",
            "uuid",
            "hex",
            "sid",
            "hash",
            "trunc",
        }
        tokens = set(re.findall(r"[a-z0-9]+", value.lower()))
        return {token for token in tokens if token and token not in placeholder_tokens}

    def _get_template_similarity_candidates(self) -> List[Tuple[int, set[str]]]:
        cached = getattr(self, "_template_similarity_candidates", None)
        if cached is not None:
            return cached

        candidates: List[Tuple[int, set[str]]] = []
        if hasattr(self.vocab, "itos"):
            for idx, template in enumerate(self.vocab.itos):
                template_text = str(template)
                if template_text.lower() == "padding":
                    continue
                tokens = self._template_tokens(template_text)
                if len(tokens) >= 5:
                    candidates.append((idx, tokens))
        self._template_similarity_candidates = candidates
        return candidates

    def _event_to_similar_index(self, event_template: str) -> int | None:
        cache = getattr(self, "_template_similarity_cache", {})
        if event_template in cache:
            return cache[event_template]

        event_tokens = self._template_tokens(event_template)
        if len(event_tokens) < 4:
            return None

        threshold = float(getattr(self, "template_similarity_threshold", 0.65))
        best_index: int | None = None
        best_rank: Tuple[int, float, int] = (0, 0.0, 0)
        for idx, candidate_tokens in self._get_template_similarity_candidates():
            matched = len(candidate_tokens & event_tokens)
            if matched < 4:
                continue
            score = matched / len(candidate_tokens)
            if score < threshold:
                continue
            rank = (matched, score, len(candidate_tokens))
            if rank > best_rank:
                best_rank = rank
                best_index = idx

        if best_index is not None:
            cache[event_template] = best_index
            self._template_similarity_cache = cache
        return best_index

    def _event_to_index(self, event_template: str) -> int:
        if hasattr(self.vocab, "stoi"):
            exact = self.vocab.stoi.get(event_template)
            if exact is not None:
                return int(exact)
        if hasattr(self.vocab, "get_event"):
            index = int(self.vocab.get_event(event_template))
        elif hasattr(self.vocab, "stoi"):
            index = int(self.vocab.stoi.get(event_template, 0))
        else:
            return 0

        if index == self.unk_index and getattr(
            self, "template_similarity_enabled", False
        ):
            similar_index = self._event_to_similar_index(event_template)
            if similar_index is not None:
                return similar_index
        return index

    def _index_to_event(self, idx: int) -> str:
        if hasattr(self.vocab, "itos") and 0 <= idx < len(self.vocab.itos):
            return str(self.vocab.itos[idx])
        return f"event_{idx}"

    def _is_ipv4(self, value: str) -> bool:
        return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value))

    def _is_hash(self, value: str) -> bool:
        return bool(re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$", value))

    def _is_domain(self, value: str) -> bool:
        return bool(re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", value))


def detect_anomalies_in_logs(
    parsed_df: pd.DataFrame,
    model_path: str,
    vocab_path: str,
    **kwargs,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    detector = DeepLogDetector(model_path, vocab_path, **kwargs)
    results_df = detector.detect_anomalies(parsed_df)
    anomalies_df = detector.get_anomalous_windows(results_df)
    return results_df, anomalies_df
