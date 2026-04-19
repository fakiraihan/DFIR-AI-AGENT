"""
Report generation module.

MVP scope:
- Structured investigation report
- JSON + Markdown output
- No chatbot integration in this module
"""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple


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
        raw_summary_text = (
            investigation_state.get("investigation_summary") or "No summary available."
        )
        raw_recommendations = investigation_state.get("recommendations", []) or []

        severity = self._calculate_severity(tool_results, anomalies)
        generated_at = datetime.now().isoformat()
        ioc_analysis = self._build_ioc_analysis(iocs, tool_results)
        recommendations = self._normalize_recommendations(
            raw_recommendations or self._default_recommendations(severity),
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
                anomalies, tool_results, ioc_analysis
            ),
            "ioc_analysis": ioc_analysis,
            "attack_timeline": self._build_timeline(timeline, generated_at),
            "recommendations": recommendations,
            "evidence_references": self._build_evidence_references(
                anomalies, tool_results
            ),
        }

        return report

    def save_report(self, report: Dict[str, Any], output_dir: str) -> str:
        """Save report as JSON and Markdown. Return Markdown path."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report_id = report["metadata"]["report_id"]

        json_file = output_path / f"{report_id}.json"
        with open(json_file, "w", encoding="utf-8") as file_obj:
            json.dump(report, file_obj, indent=2, ensure_ascii=False)

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
        cleaned_summary = self._clean_text(summary_text)
        if cleaned_summary and not self._is_low_quality_summary(cleaned_summary):
            return cleaned_summary

        executed_tool_results = [
            item for item in tool_results if not self._is_skipped_result(item)
        ]
        malicious_hits = self._count_malicious_hits(tool_results)
        suspicious_hits = self._count_suspicious_hits(tool_results)
        top_iocs = [ioc["value"] for ioc in ioc_analysis[:3]]
        top_events = self._top_anomalous_events(anomalies)
        verdict = self._derive_verdict(
            severity, malicious_hits, suspicious_hits, anomalies
        )
        top_action = (
            "; ".join(recommendations[:3])
            if recommendations
            else "Lakukan validasi manual lebih lanjut"
        )
        top_action = top_action.rstrip(" .;")

        lines = [
            "### 1. Ringkasan Insiden",
            f"Investigasi terhadap file log `{file_name}` menemukan {len(anomalies)} window anomali yang perlu ditriase lebih lanjut. Severity saat ini diklasifikasikan sebagai **{severity}** dengan verdict awal: **{verdict}**.",
            "",
            "### 2. Temuan Utama",
            f"Sistem mengekstrak {len(ioc_analysis)} IOC terkurasi dari artefak anomali. Korelasi threat intelligence menunjukkan {malicious_hits} indikator malicious dan {suspicious_hits} indikator suspicious dari total {len(executed_tool_results)} hasil enrichment.",
            "",
            "### 3. Aktivitas yang Teramati",
            f"Aktivitas dominan yang muncul dalam window anomali adalah: {top_events or 'belum ada pola event dominan yang kuat'}. Timeline investigasi saat ini memuat {len(timeline)} kejadian penting yang dapat dijadikan dasar triase lanjutan.",
            "",
            "### 4. IOC Prioritas",
            f"IOC yang paling relevan untuk ditinjau terlebih dahulu: {', '.join(top_iocs) if top_iocs else 'belum ada IOC prioritas yang cukup kuat'}.",
            "",
            "### 5. Tindak Lanjut Disarankan",
            top_action + ".",
        ]

        return "\n".join(lines).strip()

    def _build_ioc_analysis(
        self, iocs: List[Dict[str, Any]], tool_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Merge IOC list with curated threat context."""
        result_by_ioc: Dict[str, Dict[str, Any]] = {}
        for item in tool_results:
            if self._is_skipped_result(item):
                continue

            ioc_value = self._normalize_ioc_value(
                item.get("ioc") or item.get("ip") or item.get("url") or item.get("hash")
            )
            normalized_key = ioc_value.lower()
            if not normalized_key:
                continue

            existing = result_by_ioc.get(normalized_key)
            if existing is None or self._tool_result_priority(
                item
            ) > self._tool_result_priority(existing):
                result_by_ioc[normalized_key] = item

        curated: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for ioc in iocs:
            ioc_type = str(ioc.get("type", "unknown")).lower()
            value = self._normalize_ioc_value(ioc.get("value"))
            if not value or self._is_low_signal_ioc(ioc_type, value):
                continue

            key = (ioc_type, value.lower())
            tool_info = result_by_ioc.get(value.lower(), {})
            candidate = {
                "type": ioc_type,
                "value": value,
                "threat_level": self._infer_threat_level(tool_info),
                "threat_intel": self._summarize_tool_result(tool_info),
                "source_line": ioc.get("source_line"),
                "source_window": ioc.get("window_id"),
                "_priority": self._ioc_priority(ioc_type, tool_info),
            }

            existing = curated.get(key)
            if existing is None or candidate["_priority"] > existing["_priority"]:
                curated[key] = candidate

        ranked = sorted(
            curated.values(),
            key=lambda item: (-item["_priority"], item["type"], item["value"]),
        )

        for item in ranked:
            item.pop("_priority", None)

        return ranked[:25]

    def _build_technical_findings(
        self,
        anomalies: List[Dict[str, Any]],
        tool_results: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        top_events = self._top_anomalous_events(anomalies)
        malicious_hits = self._count_malicious_hits(tool_results)
        suspicious_hits = self._count_suspicious_hits(tool_results)
        unavailable_hits = sum(1 for item in tool_results if item.get("error"))

        if anomalies:
            findings.append(
                {
                    "title": "Deteksi anomali utama",
                    "detail": f"DeepLog menandai {len(anomalies)} window anomali. Event yang paling sering muncul pada window tersebut adalah {top_events or 'belum ada pola dominan'}.",
                }
            )

        if ioc_analysis:
            type_counter = Counter(ioc.get("type", "unknown") for ioc in ioc_analysis)
            distribution = ", ".join(
                f"{count} {ioc_type}" for ioc_type, count in type_counter.most_common(4)
            )
            findings.append(
                {
                    "title": "IOC terkurasi",
                    "detail": f"Sebanyak {len(ioc_analysis)} IOC bernilai analitis berhasil dipertahankan untuk investigasi lanjutan, dengan distribusi utama: {distribution}.",
                }
            )

        if malicious_hits or suspicious_hits:
            findings.append(
                {
                    "title": "Korelasi threat intelligence",
                    "detail": f"Hasil enrichment menunjukkan {malicious_hits} IOC dengan indikasi malicious dan {suspicious_hits} IOC dengan indikasi suspicious. Prioritaskan validasi IOC dengan threat level tertinggi terlebih dahulu.",
                }
            )
        elif unavailable_hits:
            findings.append(
                {
                    "title": "Keterbatasan enrichment",
                    "detail": f"Sebagian lookup threat intelligence belum tersedia atau belum terkonfigurasi ({unavailable_hits} hasil). Kesimpulan saat ini lebih banyak bertumpu pada pola anomali log dibanding reputasi eksternal.",
                }
            )

        if not findings:
            findings.append(
                {
                    "title": "Belum ada pola ancaman yang kuat",
                    "detail": "Belum ditemukan kombinasi anomali dan enrichment yang cukup kuat untuk mengonfirmasi aktivitas malicious. Investigasi lanjutan tetap disarankan untuk menutup kemungkinan false negative.",
                }
            )

        return findings

    def _build_timeline(
        self, timeline: List[Dict[str, Any]], fallback_timestamp: str
    ) -> List[Dict[str, Any]]:
        normalized = []
        for item in timeline:
            normalized.append(
                {
                    "timestamp": item.get("timestamp") or fallback_timestamp,
                    "event": item.get("event")
                    or item.get("event_template")
                    or "Anomalous event",
                    "details": self._clean_text(
                        item.get("details")
                        or item.get("description")
                        or "No details available"
                    ),
                }
            )
        return normalized

    def _build_evidence_references(
        self, anomalies: List[Dict[str, Any]], tool_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        evidence: List[Dict[str, Any]] = []

        for anomaly in anomalies[:30]:
            evidence.append(
                {
                    "type": "log_window",
                    "reference": f"window:{anomaly.get('window_id')}",
                    "description": f"Anomalous window with event '{anomaly.get('actual_event', 'unknown')}'",
                }
            )

        meaningful_tool_results = [
            result for result in tool_results if not self._is_skipped_result(result)
        ]

        for result in meaningful_tool_results[:30]:
            target = (
                result.get("ioc")
                or result.get("ip")
                or result.get("url")
                or result.get("hash")
                or "unknown"
            )
            evidence.append(
                {
                    "type": "tool_result",
                    "reference": f"{result.get('tool', 'tool')}:{target}",
                    "description": self._summarize_tool_result(result),
                }
            )

        return evidence

    def _calculate_severity(
        self, tool_results: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]
    ) -> str:
        malicious_hits = self._count_malicious_hits(tool_results)

        if malicious_hits >= 3:
            return "HIGH"
        if malicious_hits >= 1 or len(anomalies) >= 10:
            return "MEDIUM"
        return "LOW"

    def _infer_threat_level(self, tool_result: Dict[str, Any]) -> str:
        if not tool_result:
            return "low"
        if self._is_malicious_result(tool_result):
            return "high"
        if self._is_suspicious_result(tool_result):
            return "medium"
        return "low"

    def _summarize_tool_result(self, tool_result: Dict[str, Any]) -> str:
        if not tool_result:
            return "Belum ada data enrichment eksternal untuk IOC ini"

        if tool_result.get("error"):
            return self._sanitize_tool_error(tool_result)

        tool_name = str(tool_result.get("tool", "tool")).upper()
        parts: List[str] = [tool_name]

        classification = tool_result.get("classification")
        if classification:
            parts.append(f"classification={classification}")

        malicious = tool_result.get("malicious")
        if malicious is not None:
            parts.append(f"malicious={malicious}")

        suspicious = tool_result.get("suspicious")
        if suspicious is not None:
            parts.append(f"suspicious={suspicious}")

        pulse_count = tool_result.get("pulse_count")
        if pulse_count is not None:
            parts.append(f"pulse_count={pulse_count}")

        return (
            ", ".join(parts)
            if len(parts) > 1
            else f"{tool_name}: tidak ada indikator reputasi yang menonjol"
        )

    def _sanitize_tool_error(self, tool_result: Dict[str, Any]) -> str:
        tool_name = str(tool_result.get("tool", "tool")).upper()
        error_text = str(tool_result.get("error", "")).lower()

        if "api key required" in error_text or "not configured" in error_text:
            return f"{tool_name}: layanan enrichment belum terkonfigurasi"
        if "404" in error_text or "not found" in error_text:
            return f"{tool_name}: tidak ada reputasi publik yang relevan untuk IOC ini"
        if "timeout" in error_text:
            return f"{tool_name}: permintaan enrichment melebihi batas waktu"
        return f"{tool_name}: enrichment sementara tidak tersedia"

    def _default_recommendations(self, severity: str) -> List[str]:
        base = [
            "Validasi host, akun, dan proses terkait terhadap inventaris aset lokal.",
            "Pertahankan log dan artefak host terdampak untuk analisis forensik lanjutan.",
            "Monitor IOC terkait dan aktivitas serupa setidaknya selama 24 jam berikutnya.",
        ]
        if severity == "HIGH":
            return [
                "Isolasi endpoint yang terindikasi terdampak dari jaringan produksi.",
                "Blok IOC yang telah terkonfirmasi malicious pada kontrol perimeter yang relevan.",
            ] + base
        return base

    def _normalize_recommendations(
        self,
        recommendations: List[str],
        severity: str,
        anomalies: List[Dict[str, Any]],
        ioc_analysis: List[Dict[str, Any]],
    ) -> List[str]:
        normalized: List[str] = []
        seen = set()
        for recommendation in recommendations:
            cleaned = self._clean_recommendation(recommendation)
            if not cleaned:
                continue
            key = cleaned.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(cleaned)

        if not normalized:
            normalized = self._default_recommendations(severity)

        if anomalies and all("manual" not in item.lower() for item in normalized):
            normalized.append(
                "Lakukan validasi manual pada window anomali prioritas untuk memastikan konteks proses, user, dan parent process."
            )
        if ioc_analysis and all("ioc" not in item.lower() for item in normalized):
            normalized.append(
                "Prioritaskan pengecekan IOC dengan threat level tertinggi pada endpoint, firewall, proxy, atau kontrol deteksi yang tersedia."
            )

        return normalized[:8]

    def _clean_recommendation(self, text: str) -> str:
        cleaned = self._clean_text(text)
        cleaned = re.sub(r"^[^A-Za-zÀ-ÿ0-9]+", "", cleaned).strip()
        cleaned = cleaned.replace("persist ence", "persistence")
        replacements = {
            "Verify sistem": "Verifikasi sistem",
            "Collect additional context": "Kumpulkan konteks tambahan",
            "Enhance logging": "Tingkatkan logging",
            "Review anomali DeepLog": "Tinjau anomali DeepLog",
            "Monitor sistem": "Monitor sistem",
        }
        for source, target in replacements.items():
            if cleaned.startswith(source):
                cleaned = cleaned.replace(source, target, 1)
        return cleaned

    def _is_low_quality_summary(self, text: str) -> bool:
        placeholder_patterns = [
            r"\[[^\]]+\]",
            r"\[tanggal\]",
            r"\[jumlah\]",
            r"\[severity level\]",
            r"\[confidence level\]",
            r"error generating summary",
            r"final review and formatting",
            r"incident overview",
            r"threat identification",
            r"impact assessment",
            r"severity classification",
            r"recommended actions",
            r"mitre att&ck mapping",
            r"appendix \(jika perlu\)",
        ]
        lowered = text.lower()
        if len(text.strip()) < 80:
            return True
        template_headings = [
            "incident overview",
            "threat identification",
            "impact assessment",
            "severity classification",
            "mitre att&ck mapping",
            "attack timeline",
            "final review and formatting",
        ]
        heading_matches = sum(1 for heading in template_headings if heading in lowered)
        if heading_matches >= 2:
            return True
        return any(
            re.search(pattern, lowered, flags=re.IGNORECASE)
            for pattern in placeholder_patterns
        )

    def _top_anomalous_events(self, anomalies: List[Dict[str, Any]]) -> str:
        events = [
            str(item.get("actual_event", "")).strip()
            for item in anomalies
            if item.get("actual_event")
        ]
        if not events:
            return ""
        counts = Counter(events)
        return ", ".join(
            f"{event} ({count}x)" for event, count in counts.most_common(3)
        )

    def _count_malicious_hits(self, tool_results: List[Dict[str, Any]]) -> int:
        return self._count_unique_hits(tool_results, self._is_malicious_result)

    def _count_suspicious_hits(self, tool_results: List[Dict[str, Any]]) -> int:
        return self._count_unique_hits(tool_results, self._is_suspicious_result)

    def _count_unique_hits(self, tool_results: List[Dict[str, Any]], predicate) -> int:
        seen = set()
        for result in tool_results:
            if not predicate(result):
                continue

            ioc_value = self._normalize_ioc_value(
                result.get("ioc")
                or result.get("ip")
                or result.get("url")
                or result.get("hash")
            )
            key = ioc_value.lower() if ioc_value else f"__result__:{id(result)}"
            seen.add(key)
        return len(seen)

    def _tool_result_priority(self, tool_result: Dict[str, Any]) -> int:
        if self._is_skipped_result(tool_result):
            return 0
        if self._is_malicious_result(tool_result):
            return 3
        if self._is_suspicious_result(tool_result):
            return 2
        if tool_result and not tool_result.get("error"):
            return 1
        return 0

    def _is_skipped_result(self, tool_result: Dict[str, Any]) -> bool:
        if not tool_result:
            return False
        return tool_result.get("status") == "skipped" or bool(tool_result.get("skipped"))

    def _derive_verdict(
        self,
        severity: str,
        malicious_hits: int,
        suspicious_hits: int,
        anomalies: List[Dict[str, Any]],
    ) -> str:
        if malicious_hits > 0:
            return "indikasi ancaman aktif perlu diprioritaskan"
        if suspicious_hits > 0 or severity == "MEDIUM":
            return "aktivitas mencurigakan memerlukan validasi manual"
        if anomalies:
            return "anomali terdeteksi namun belum ada konfirmasi threat intelligence yang kuat"
        return "tidak ada indikasi ancaman yang cukup kuat pada data saat ini"

    def _ioc_priority(self, ioc_type: str, tool_info: Dict[str, Any]) -> int:
        base = {"ip": 5, "url": 4, "sha256": 4, "md5": 3, "domain": 2}.get(ioc_type, 1)
        if self._is_malicious_result(tool_info):
            base += 5
        elif self._is_suspicious_result(tool_info):
            base += 3
        elif tool_info and not tool_info.get("error") and not self._is_skipped_result(tool_info):
            base += 1
        return base

    def _is_malicious_result(self, tool_result: Dict[str, Any]) -> bool:
        if not tool_result:
            return False
        return (
            tool_result.get("classification") == "malicious"
            or int(tool_result.get("malicious", 0) or 0) > 0
        )

    def _is_suspicious_result(self, tool_result: Dict[str, Any]) -> bool:
        if not tool_result or self._is_malicious_result(tool_result):
            return False
        return (
            tool_result.get("classification") == "suspicious"
            or int(tool_result.get("suspicious", 0) or 0) > 0
        )

    def _normalize_ioc_value(self, value: Any) -> str:
        return str(value).strip() if value is not None else ""

    def _is_low_signal_ioc(self, ioc_type: str, value: str) -> bool:
        lowered = value.lower()
        if not lowered:
            return True
        if ioc_type == "domain":
            if lowered.endswith(
                (".exe", ".dll", ".tmp", ".sys", ".dat", ".bat", ".cmd", ".ps1", ".vbs")
            ):
                return True
            if lowered in {"localhost", "microsoft.net"}:
                return True
        return False

    def _clean_text(self, text: Any) -> str:
        if text is None:
            return ""
        cleaned = str(text)
        cleaned = cleaned.replace("<|reserved_special_token_103|>", "")
        cleaned = cleaned.replace("persist ence", "persistence")
        cleaned = re.sub(r"\r\n?", "\n", cleaned)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip()

    def _to_markdown(self, report: Dict[str, Any]) -> str:
        metadata = report.get("metadata", {})
        lines = [
            "# DFIR Investigation Report",
            "",
            f"- Report ID: {metadata.get('report_id', '-')}",
            f"- Session ID: {metadata.get('session_id', '-')}",
            f"- Timestamp: {metadata.get('timestamp', '-')}",
            f"- Log File: {metadata.get('log_file', '-')}",
            f"- Severity: {metadata.get('severity', '-')}",
            "",
            "## Executive Summary",
            report.get("executive_summary", "No summary available."),
            "",
            "## Technical Findings",
        ]

        for finding in report.get("technical_findings", []):
            lines.append(
                f"- {finding.get('title', 'Finding')}: {finding.get('detail', '-')}"
            )

        lines.append("")
        lines.append("## IOC List")
        for ioc in report.get("ioc_analysis", []):
            intel = ioc.get("threat_intel", "-")
            lines.append(
                f"- {ioc.get('type', 'unknown')} `{ioc.get('value', '-')}` | threat={ioc.get('threat_level', 'low')} | source_line={ioc.get('source_line', '-')} | intel={intel}"
            )

        lines.append("")
        lines.append("## Attack Timeline")
        for event in report.get("attack_timeline", []):
            lines.append(
                f"- {event.get('timestamp', '-')} | {event.get('event', '-')} | {event.get('details', '-')}"
            )

        lines.append("")
        lines.append("## Recommendations")
        for recommendation in report.get("recommendations", []):
            lines.append(f"- {recommendation}")

        lines.append("")
        lines.append("## Evidence References")
        for evidence in report.get("evidence_references", []):
            lines.append(
                f"- {evidence.get('type', 'evidence')} `{evidence.get('reference', '-')}` | {evidence.get('description', '-')}"
            )

        return "\n".join(lines) + "\n"
