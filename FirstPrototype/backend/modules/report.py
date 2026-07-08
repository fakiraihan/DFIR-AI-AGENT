"""
Report generation module.

MVP scope:
- Structured investigation report
- JSON + Markdown output
- No chatbot integration in this module
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from .report_modules import common as report_common
from .report_modules import findings as report_findings
from .report_modules import ioc_analysis as report_ioc_analysis
from .report_modules import markdown as report_markdown
from .report_modules import recommendations as report_recommendations
from .report_modules import summary as report_summary
from .report_modules import v2 as report_v2


class ReportGenerator:
    """Generate structured DFIR investigation reports."""

    def generate_report(
        self,
        session_id: str,
        file_name: str,
        investigation_state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build the report object used by API and frontend."""
        anomalies = investigation_state.get("anomalies", []) or []
        iocs = investigation_state.get("iocs_extracted", []) or []
        tool_results = investigation_state.get("tool_results", []) or []
        timeline = investigation_state.get("attack_timeline", []) or []
        total_extracted_iocs = len(iocs)
        raw_summary_text = (
            investigation_state.get("investigation_summary") or "No summary available."
        )
        raw_recommendations = investigation_state.get("recommendations", []) or []

        severity = self._calculate_severity(tool_results, anomalies)
        generated_at = datetime.now().isoformat()
        ioc_analysis = self._build_ioc_analysis(iocs, tool_results)
        contextual_recommendations = self._build_contextual_recommendations(
            severity,
            anomalies,
            ioc_analysis,
            tool_results,
            timeline,
        )
        recommendations = self._normalize_recommendations(
            contextual_recommendations + raw_recommendations,
            severity,
            anomalies,
            ioc_analysis,
        )
        executive_summary = self._build_executive_summary(
            raw_summary_text,
            severity,
            file_name,
            anomalies,
            ioc_analysis,
            tool_results,
            timeline,
            recommendations,
        )
        attack_timeline = self._build_timeline(timeline, generated_at)
        evidence_references = self._build_evidence_references(
            anomalies, tool_results
        )

        report = {
            "metadata": {
                "session_id": session_id,
                "report_id": f"DFIR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "timestamp": generated_at,
                "log_file": file_name,
                "model": "Foundation-Sec-8B + DeepLog",
                "severity": severity,
            },
            "executive_summary": executive_summary,
            "technical_findings": self._build_technical_findings(
                anomalies, tool_results, ioc_analysis, total_extracted_iocs
            ),
            "ioc_analysis": ioc_analysis,
            "attack_timeline": attack_timeline,
            "recommendations": recommendations,
            "evidence_references": evidence_references,
        }

        self._add_report_v2_sections(
            report,
            session_id,
            file_name,
            generated_at,
            anomalies,
            ioc_analysis,
            tool_results,
            timeline,
            attack_timeline,
            total_extracted_iocs,
        )

        return report

    def save_report(self, report: Dict[str, Any], output_dir: str) -> str:
        """Save report as JSON and Markdown. Return Markdown path."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report_id = report["metadata"]["report_id"]
        json_file = output_path / f"{report_id}.json"

        def _default(obj):
            if hasattr(obj, "item"):
                return obj.item()
            if hasattr(obj, "tolist"):
                return obj.tolist()
            raise TypeError(
                f"Object of type {type(obj).__name__} is not JSON serializable"
            )

        with open(json_file, "w", encoding="utf-8") as file_obj:
            json.dump(report, file_obj, indent=2, ensure_ascii=False, default=_default)

        markdown_file = output_path / f"{report_id}.md"
        markdown_text = self._to_markdown(report)
        with open(markdown_file, "w", encoding="utf-8") as file_obj:
            file_obj.write(markdown_text)

        print(f"JSON report saved to: {json_file}")
        print(f"Markdown report saved to: {markdown_file}")

        return str(markdown_file)

    def _build_executive_summary(
        self,
        summary_text: str,
        severity: str,
        file_name: str,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
        recommendations: List[str],
    ) -> str:
        return report_summary.build_executive_summary(
            summary_text,
            severity,
            file_name,
            anomalies,
            ioc_analysis,
            tool_results,
            timeline,
            recommendations,
        )

    def _build_ioc_analysis(
        self, iocs: List[Dict[str, Any]], tool_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        return report_ioc_analysis.build_ioc_analysis(iocs, tool_results)

    def _build_technical_findings(
        self,
        anomalies: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
        total_extracted_iocs: int = 0,
    ) -> List[Dict[str, Any]]:
        return report_findings.build_technical_findings(
            anomalies, tool_results, ioc_analysis, total_extracted_iocs
        )

    def _build_timeline(
        self, timeline: List[Dict[str, Any]], fallback_timestamp: str
    ) -> List[Dict[str, Any]]:
        return report_findings.build_timeline(timeline, fallback_timestamp)

    def _build_evidence_references(
        self, anomalies: List[Dict[str, Any]], tool_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        return report_findings.build_evidence_references(anomalies, tool_results)

    def _add_report_v2_sections(
        self,
        report: Dict[str, Any],
        session_id: str,
        file_name: str,
        generated_at: str,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        raw_timeline: List[Dict[str, Any]],
        attack_timeline: List[Dict[str, Any]],
        total_extracted_iocs: int = 0,
    ) -> None:
        return report_v2.add_report_v2_sections(
            report,
            session_id,
            file_name,
            generated_at,
            anomalies,
            ioc_analysis,
            tool_results,
            raw_timeline,
            attack_timeline,
            total_extracted_iocs,
        )

    def _build_standards_profile(self) -> Dict[str, Any]:
        return report_v2.build_standards_profile()

    def _build_case_overview(
        self,
        session_id: str,
        file_name: str,
        generated_at: str,
        severity: str,
    ) -> Dict[str, Any]:
        return report_v2.build_case_overview(
            session_id, file_name, generated_at, severity
        )

    def _build_objectives_scope(self, file_name: str) -> Dict[str, Any]:
        return report_v2.build_objectives_scope(file_name)

    def _build_methodology(self) -> Dict[str, Any]:
        return report_v2.build_methodology()

    def _build_evidence_provenance(
        self,
        file_name: str,
        anomalies: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return report_v2.build_evidence_provenance(
            file_name, anomalies, tool_results, timeline
        )

    def _build_detection_analysis(
        self,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        technical_findings: List[Dict[str, Any]],
        evidence_items: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return report_v2.build_detection_analysis(
            anomalies,
            ioc_analysis,
            tool_results,
            technical_findings,
            evidence_items,
        )

    def _build_mitre_attack_mapping(
        self,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
        evidence_items: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return report_v2.build_mitre_attack_mapping(
            anomalies, ioc_analysis, evidence_items
        )

    def _record_mitre_mapping(
        self,
        mapped: Dict[str, Dict[str, Any]],
        *,
        technique_id: str,
        tactic: str,
        technique_name: str,
        confidence: str,
        evidence_ids: List[str],
        rationale: str,
    ) -> None:
        return report_v2.record_mitre_mapping(
            mapped,
            technique_id=technique_id,
            tactic=tactic,
            technique_name=technique_name,
            confidence=confidence,
            evidence_ids=evidence_ids,
            rationale=rationale,
        )

    def _build_impact_assessment(self) -> Dict[str, Any]:
        return report_v2.build_impact_assessment()

    def _build_limitations_confidence(
        self,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return report_v2.build_limitations_confidence(
            anomalies, ioc_analysis, tool_results, timeline
        )

    def _build_appendices(
        self,
        ioc_analysis: List[Dict[str, Any]],
        raw_timeline: List[Dict[str, Any]],
        attack_timeline: List[Dict[str, Any]],
        fallback_timestamp: str,
        evidence_items: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        return report_v2.build_appendices(
            ioc_analysis,
            raw_timeline,
            attack_timeline,
            fallback_timestamp,
            evidence_items,
        )

    def _anomaly_reference(self, anomaly: Dict[str, Any]) -> str:
        return report_v2.anomaly_reference(anomaly)

    def _tool_result_target(self, result: Dict[str, Any]) -> str:
        return report_v2.tool_result_target(result)

    def _timeline_reference(self, item: Dict[str, Any]) -> str:
        return report_v2.timeline_reference(item)

    def _timestamp_for_reference(
        self, reference: str, timeline: List[Dict[str, Any]]
    ) -> str:
        return report_v2.timestamp_for_reference(reference, timeline)

    def _reference_to_evidence_ids(
        self, evidence_items: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        return report_v2.reference_to_evidence_ids(evidence_items)

    def _reference_to_first_evidence_id(
        self, evidence_items: List[Dict[str, Any]]
    ) -> Dict[str, str]:
        return report_v2.reference_to_first_evidence_id(evidence_items)

    def _mitre_context(self, anomaly: Dict[str, Any]) -> str:
        return report_v2.mitre_context(anomaly)

    def _calculate_severity(
        self, tool_results: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]
    ) -> str:
        return report_common.calculate_severity(tool_results, anomalies)

    def _infer_threat_level(self, tool_result: Dict[str, Any]) -> str:
        return report_common.infer_threat_level(tool_result)

    def _summarize_tool_result(self, tool_result: Dict[str, Any]) -> str:
        return report_common.summarize_tool_result(tool_result)

    def _sanitize_tool_error(self, tool_result: Dict[str, Any]) -> str:
        return report_common.sanitize_tool_error(tool_result)

    def _build_contextual_recommendations(
        self,
        severity: str,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
    ) -> List[str]:
        return report_recommendations.build_contextual_recommendations(
            severity, anomalies, ioc_analysis, tool_results, timeline
        )

    def _default_recommendations(self, severity: str) -> List[str]:
        return report_recommendations.default_recommendations(severity)

    def _normalize_recommendations(
        self,
        recommendations: List[str],
        severity: str,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
    ) -> List[str]:
        return report_recommendations.normalize_recommendations(
            recommendations, severity, anomalies, ioc_analysis
        )

    def _select_priority_anomaly(
        self, anomalies: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return report_recommendations.select_priority_anomaly(anomalies)

    def _format_anomaly_context(self, anomaly: Dict[str, Any]) -> str:
        return report_recommendations.format_anomaly_context(anomaly)

    def _collect_affected_artifacts(self, anomalies: List[Dict[str, Any]]) -> str:
        return report_recommendations.collect_affected_artifacts(anomalies)

    def _format_ioc_values(self, iocs: List[Dict[str, Any]]) -> str:
        return report_recommendations.format_ioc_values(iocs)

    def _clean_recommendation(self, text: str) -> str:
        return report_recommendations.clean_recommendation(text)

    def _is_low_quality_summary(self, text: str) -> bool:
        return report_summary.is_low_quality_summary(text)

    def _summary_matches_evidence(
        self,
        text: str,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
    ) -> bool:
        return report_summary.summary_matches_evidence(
            text, anomalies, ioc_analysis, tool_results, timeline
        )

    def _summary_evidence_terms(
        self,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
    ) -> List[str]:
        return report_summary.summary_evidence_terms(
            anomalies, ioc_analysis, tool_results, timeline
        )

    def _top_anomalous_events(self, anomalies: List[Dict[str, Any]]) -> str:
        return report_common.top_anomalous_events(anomalies)

    def _count_malicious_hits(self, tool_results: List[Dict[str, Any]]) -> int:
        return report_common.count_malicious_hits(tool_results)

    def _count_suspicious_hits(self, tool_results: List[Dict[str, Any]]) -> int:
        return report_common.count_suspicious_hits(tool_results)

    def _count_unique_hits(self, tool_results: List[Dict[str, Any]], predicate) -> int:
        return report_common.count_unique_hits(tool_results, predicate)

    def _tool_result_priority(self, tool_result: Dict[str, Any]) -> int:
        return report_common.tool_result_priority(tool_result)

    def _is_skipped_result(self, tool_result: Dict[str, Any]) -> bool:
        return report_common.is_skipped_result(tool_result)

    def _derive_verdict(
        self,
        severity: str,
        malicious_hits: int,
        suspicious_hits: int,
        anomalies: List[Dict[str, Any]],
    ) -> str:
        return report_common.derive_verdict(
            severity, malicious_hits, suspicious_hits, anomalies
        )

    def _ioc_priority(self, ioc_type: str, tool_info: Dict[str, Any]) -> int:
        return report_common.ioc_priority(ioc_type, tool_info)

    def _is_malicious_result(self, tool_result: Dict[str, Any]) -> bool:
        return report_common.is_malicious_result(tool_result)

    def _is_suspicious_result(self, tool_result: Dict[str, Any]) -> bool:
        return report_common.is_suspicious_result(tool_result)

    def _safe_positive_count(self, value: Any) -> int:
        return report_common.safe_positive_count(value)

    def _normalize_ioc_value(self, value: Any) -> str:
        return report_common.normalize_ioc_value(value)

    def _is_low_signal_ioc(self, ioc_type: str, value: str) -> bool:
        return report_common.is_low_signal_ioc(ioc_type, value)

    def _clean_text(self, text: Any) -> str:
        return report_common.clean_text(text)

    def _to_markdown(self, report: Dict[str, Any]) -> str:
        return report_markdown.to_markdown(report)
