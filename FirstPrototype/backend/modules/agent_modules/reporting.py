"""Final summary/report node helpers for the DFIR agent."""

from collections import Counter
from typing import Any, Dict, Mapping
import re
import time

from modules.agent_modules import recommendations as agent_recommendations
from modules.report_modules import summary as report_summary


def _emit_terminal(agent: Any, line: str, *, progress: int | None = None, level: str = "info") -> None:
    emit = getattr(agent, "_emit_terminal", None)
    if callable(emit):
        emit(line, progress=progress, level=level)


def _compact_text(value: Any, *, max_chars: int = 180) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def _extract_eval_tactic(state: Mapping[str, Any]) -> str:
    brief = str(state.get("evaluation_evidence_brief") or "")
    for pattern in (
        r"tactic_folder:\s*([^\n]+)",
        r"Tactic lock:\s*analyze this case as\s*([^\n.]+)",
    ):
        match = re.search(pattern, brief, flags=re.IGNORECASE)
        if match:
            return _compact_text(match.group(1), max_chars=80)
    return ""


def _extract_brief_field(state: Mapping[str, Any], field_name: str) -> str:
    brief = str(state.get("evaluation_evidence_brief") or "")
    pattern = rf"^\s*-\s*{re.escape(field_name)}:\s*(.+?)\s*$"
    match = re.search(pattern, brief, flags=re.IGNORECASE | re.MULTILINE)
    if not match:
        return ""
    return _compact_text(match.group(1), max_chars=180)


def _extract_brief_bullets(
    state: Mapping[str, Any],
    section_name: str,
    *,
    max_items: int = 4,
) -> list[str]:
    brief = str(state.get("evaluation_evidence_brief") or "")
    match = re.search(
        rf"^###\s+{re.escape(section_name)}\s*$",
        brief,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    if not match:
        return []
    bullets: list[str] = []
    for line in brief[match.end() :].splitlines():
        if line.startswith("### "):
            break
        stripped = line.strip()
        if stripped.startswith("- "):
            bullets.append(_compact_text(stripped[2:], max_chars=180))
        if len(bullets) >= max_items:
            break
    return bullets


def _brief_field_int(state: Mapping[str, Any], field_name: str) -> int:
    value = _extract_brief_field(state, field_name)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _brief_field_bool(state: Mapping[str, Any], field_name: str) -> bool:
    return _extract_brief_field(state, field_name).strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
    }


def _append_evidence_boundary_notes(
    response: str,
    state: Mapping[str, Any],
) -> str:
    text = str(response or "").strip()
    lowered = text.lower()
    notes: list[str] = []

    if _brief_field_bool(state, "max_lines_reached") and not any(
        token in lowered for token in ("parser cap", "max_lines", "cap tercapai")
    ):
        max_lines = _extract_brief_field(state, "max_lines") or "configured limit"
        notes.append(
            f"Parsing mencapai cap {max_lines}; cakupan EVTX tidak boleh dianggap lengkap."
        )

    if _brief_field_int(state, "private/internal_iocs") > 0 and not any(
        token in lowered for token in ("private", "internal", "lokal", "local")
    ):
        notes.append(
            "IOC private/internal diperlakukan sebagai telemetry lokal; status malicious membutuhkan korelasi tool atau telemetry tambahan."
        )

    tool_status_counts = _extract_brief_field(state, "tool_status_counts")
    if (
        tool_status_counts
        and tool_status_counts.lower() != "none"
        and any(token in tool_status_counts.lower() for token in ("error", "no_result", "hash_not_found"))
        and not any(token in lowered for token in ("enrichment", "no_result", "error", "limitasi", "limitation"))
    ):
        notes.append(
            f"Hasil enrichment memiliki batasan status ({tool_status_counts}); status tersebut bukan bukti malicious."
        )

    if not notes:
        return text
    return text + "\n\n### Catatan Batas Evidence\n" + "\n".join(
        f"- {note}" for note in notes
    )


def _format_top_events(state: Mapping[str, Any]) -> str:
    events = [
        str(item.get("actual_event") or "").strip()
        for item in state.get("anomalies", []) or []
        if item.get("actual_event")
    ]
    if not events:
        return "belum ada event dominan yang dapat dirangkum"
    counts = Counter(events)
    return ", ".join(
        f"{_compact_text(event, max_chars=140)} ({count}x)"
        for event, count in counts.most_common(3)
    )


def _format_ioc_sample(state: Mapping[str, Any]) -> str:
    values = []
    for ioc in state.get("iocs_extracted", []) or []:
        value = ioc.get("value") or ioc.get("ioc")
        ioc_type = ioc.get("type") or ioc.get("ioc_type") or "ioc"
        if value:
            values.append(f"{ioc_type} `{_compact_text(value, max_chars=90)}`")
        if len(values) >= 5:
            break
    return ", ".join(values) if values else "tidak ada IOC prioritas"


def _is_prompt_echo_response(text: str) -> bool:
    if report_summary.is_low_quality_summary(text):
        return True

    stripped = str(text or "").strip()
    lowered = text.lower()
    nonblank_lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    guideline_markers = (
        "avoid",
        "do not",
        "jangan",
        "placeholder",
        "template",
        "speculation",
        "overstatement",
        "understatement",
        "technical jargon",
        "output requirement",
        "writing guideline",
        "prompt",
        "instruction",
        "checklist",
    )
    evidence_markers = (
        "eventid",
        "window ",
        "ioc",
        "host=",
        "user=",
        "process=",
        "registry",
        "tool result",
        "timeline",
    )
    looks_like_instruction_line = (
        len(stripped) <= 500
        and 1 <= len(nonblank_lines) <= 3
        and nonblank_lines[0].lstrip("-*0123456789. ").lower().startswith(
            ("avoid", "do not", "jangan")
        )
    )
    guideline_marker_count = sum(
        1 for marker in guideline_markers if marker in lowered
    )
    if (
        looks_like_instruction_line
        and guideline_marker_count >= 2
        and not any(marker in lowered for marker in evidence_markers)
    ):
        return True

    echo_markers = [
        "paragraf 1: **incident overview**",
        "if no malicious iocs are confirmed",
        "avoid overclaiming severity",
        "kapan investigasi dilakukan",
        "berapa anomali ditemukan",
        "generate comprehensive report",
        "writing guidelines",
        "output requirements",
        "thought 1:",
        "question:",
    ]
    return any(marker in lowered for marker in echo_markers)


def _build_evidence_bound_summary(agent: Any, state: Mapping[str, Any]) -> str:
    anomalies = state.get("anomalies", []) or []
    tool_results = state.get("tool_results", []) or []
    timeline = state.get("attack_timeline", []) or []
    malicious_count = sum(
        1 for result in tool_results if agent._is_malicious_tool_result(result)
    )
    suspicious_count = sum(
        1 for result in tool_results if agent._is_suspicious_tool_result(result)
    )
    tactic = _extract_eval_tactic(state)
    tactic_sentence = f" Fokus taktik evaluasi adalah {tactic}." if tactic else ""
    evtx_relative_path = _extract_brief_field(state, "evtx_relative_path")
    parsed_events = _extract_brief_field(state, "parsed_events")
    max_lines = _extract_brief_field(state, "max_lines")
    max_lines_reached = _extract_brief_field(state, "max_lines_reached")
    internal_ioc_count = _brief_field_int(state, "private/internal_iocs")
    expected_focus = _extract_brief_bullets(state, "Expected Focus", max_items=4)
    tactic_guidance = [
        item
        for item in _extract_brief_bullets(
            state, "Tactic-Specific Guidance", max_items=6
        )
        if not item.lower().startswith("tactic lock:")
        and not item.lower().startswith("do not switch tactic")
    ][:3]
    priority_anomaly = (
        agent_recommendations.select_tactic_priority_anomaly(anomalies, tactic)
        or agent._select_priority_anomaly(anomalies)
    )
    priority_context = agent._format_anomaly_recommendation_context(priority_anomaly)
    priority_window = priority_anomaly.get("window_id") if priority_anomaly else None
    priority_reference = (
        f"window {priority_window} ({priority_context})"
        if priority_window is not None
        else priority_context
    )
    artifact_context = agent._format_anomaly_artifacts(priority_anomaly)

    lines = [
        "### Ringkasan Evidence-Bound",
        (
            f"Investigasi menemukan {len(anomalies)} window anomali dan "
            f"{len(state.get('iocs_extracted', []) or [])} IOC dari evidence yang tersedia."
            f"{tactic_sentence} Event utama yang perlu ditriase adalah "
            f"{_format_top_events(state)}."
        ),
        "",
        "### Konteks Evaluasi dan Batas Data",
        (
            f"EVTX yang dievaluasi: {evtx_relative_path or 'tidak tersedia'}. "
            f"Parsed events: {parsed_events or 'tidak diketahui'}; "
            f"parser cap: {max_lines or 'tidak diketahui'}; "
            f"cap tercapai: {max_lines_reached or 'tidak diketahui'}."
        ),
        (
            "Expected focus: "
            + ("; ".join(expected_focus) if expected_focus else "tidak tersedia")
            + "."
        ),
        (
            "Panduan taktik: "
            + ("; ".join(tactic_guidance) if tactic_guidance else "gunakan evidence taktik yang tersedia")
            + "."
        ),
        "",
        "### Kalibrasi Severity dan Confidence",
        (
            f"Threat intelligence menunjukkan {malicious_count} indikator malicious "
            f"dan {suspicious_count} indikator suspicious dari {len(tool_results)} hasil enrichment. "
            "Anomaly count diperlakukan sebagai volume deteksi, bukan bukti compromise."
        ),
        "",
        "### Evidence Prioritas",
        (
            f"Prioritas triase adalah {priority_reference}. IOC yang perlu dikorelasikan: "
            f"{_format_ioc_sample(state)}."
        ),
        "",
        "### Limitasi",
        (
            "Kesimpulan dibatasi pada log, IOC, tool result, dan timeline yang tersedia. "
            "Klaim malware, C2, exfiltration, credential theft, atau compromise final "
            "tidak dibuat tanpa evidence positif tambahan."
        ),
    ]
    if internal_ioc_count > 0:
        lines.append(
            f"{internal_ioc_count} IOC private/internal diperlakukan sebagai telemetry lokal; status malicious membutuhkan korelasi tool atau telemetry tambahan."
        )
    if _brief_field_bool(state, "max_lines_reached"):
        lines.append(
            f"Parsing mencapai cap {max_lines or 'configured limit'}; cakupan EVTX tidak boleh dianggap lengkap."
        )
    lines.extend(
        [
            "",
            "### Tindak Lanjut",
            (
                f"Review raw log di sekitar {priority_reference}; korelasikan dengan EDR, DNS, "
                "proxy, firewall, asset inventory, serta baseline operasional."
            ),
        ]
    )
    if artifact_context:
        lines.append(f"Kumpulkan artefak terkait {artifact_context}.")
    if timeline:
        lines.append(
            f"Gunakan {len(timeline)} item timeline untuk merekonstruksi urutan kejadian."
        )
    tactic_recommendations = agent_recommendations.generate_tactic_specific_recommendations(
        state,
        summarize_anomaly_details=agent._summarize_anomaly_details,
        tactic=tactic,
    )
    if tactic_recommendations:
        lines.extend(["", "### Tindak Lanjut Tactic-Specific"])
        lines.extend(f"- {item}" for item in tactic_recommendations[:4])
    return "\n".join(lines).strip()


def context_only_summary(agent: Any, state: Mapping[str, Any]) -> Dict[str, Any]:
    """Finish safely when anomaly context exists but no valid IOC was extracted."""
    anomaly_count = len(state.get("anomalies") or [])
    reason = "No valid IOC was extracted from the anomalous log context."
    summary = (
        f"Investigasi bersifat inconclusive: {anomaly_count} window anomali tersedia, "
        "tetapi tidak ada IOC valid untuk enrichment threat intelligence. "
        "Kesimpulan malicious tidak dibuat tanpa bukti IOC atau korelasi eksternal."
    )
    recommendations = [
        "Lakukan review manual pada raw log di window anomali prioritas untuk mencari host, user, process tree, command line, dan koneksi jaringan.",
        "Korelasikan event dengan sumber internal seperti EDR, DNS, proxy, firewall, dan asset inventory sebelum eskalasi insiden.",
    ]
    return {
        "investigation_summary": summary,
        "recommendations": recommendations,
        "investigation_status": "inconclusive",
        "investigation_confidence": 0.0,
        "confidence_factors": [reason],
        "supporting_evidence": [],
        "inconclusive_reason": reason,
        "current_stage": "completed",
        "completed": True,
        "reasoning_steps": [reason],
        "agent_trace": [
            agent._agent_trace_event("context_only_summary", "completed", reason)
        ],
    }


def inconclusive_correlation(agent: Any, state: Mapping[str, Any]) -> Dict[str, Any]:
    """Set a safe inconclusive state when enrichment produced no usable evidence."""
    reason = "Threat-intel enrichment returned no successful non-skipped evidence."
    summary = (
        "Investigasi bersifat inconclusive: IOC berhasil diekstrak, tetapi lookup threat intelligence "
        "tidak menghasilkan evidence sukses yang dapat dijadikan dasar supporting evidence. "
        "Tidak ada klaim malicious/benign final tanpa validasi manual tambahan."
    )
    recommendations = agent._generate_default_recommendations(state) + [
        "Ulangi enrichment dengan API key/sumber internal yang tersedia dan dokumentasikan tool yang gagal atau dilewati.",
        "Validasi IOC terhadap telemetry lokal sebelum membuat keputusan containment atau closure.",
    ]
    return {
        "correlation_analysis": summary,
        "investigation_status": "inconclusive",
        "investigation_confidence": 0.0,
        "confidence_factors": [reason],
        "supporting_evidence": [],
        "inconclusive_reason": reason,
        "recommendations": recommendations[:10],
        "current_stage": "inconclusive_correlation_complete",
        "reasoning_steps": [reason],
        "agent_trace": [
            agent._agent_trace_event("inconclusive_correlation", "completed", reason)
        ],
    }


def generate_summary(agent: Any, state: Mapping[str, Any]) -> Dict[str, Any]:
    """Generate final investigation summary using the configured LLM."""
    if agent.status_callback and agent.session_id:
        agent.status_callback(
            agent.session_id, "ai_agent", "AI sedang menulis summary...", 83
        )

    print("\n=== STAGE 6: REPORT GENERATION ===")
    print("Generating comprehensive investigation summary with LLM...")
    _emit_terminal(
        agent,
        "=" * 60 + "\nSTAGE 6: REPORT GENERATION\n" + "=" * 60,
        progress=83,
        level="stage",
    )
    _emit_terminal(agent, "Generating comprehensive investigation summary with LLM...", progress=83)

    if state.get("investigation_status") == "inconclusive":
        reason = (
            state.get("inconclusive_reason")
            or "Evidence was insufficient for a conclusive verdict."
        )
        summary = state.get("correlation_analysis") or state.get("investigation_summary")
        confidence_factors = list(state.get("confidence_factors") or [reason])
        if state.get("anomalies") and (
            not summary
            or report_summary.is_low_quality_summary(str(summary))
            or "eventid" not in str(summary).lower()
        ):
            summary = (
                "Status investigasi tetap inconclusive; ringkasan berikut hanya "
                "merangkum evidence log yang tersedia dan tidak menetapkan verdict "
                "compromise final.\n\n"
                f"{_build_evidence_bound_summary(agent, state)}"
            )
            confidence_factors.append(
                "Investigation remained inconclusive; final report summarized available log evidence without overclaiming"
            )
        elif not summary:
            summary = (
                "Investigasi bersifat inconclusive karena evidence yang tersedia belum cukup "
                "untuk membuat verdict ancaman final."
            )
        recommendations = state.get("recommendations") or agent._generate_default_recommendations(
            state
        )
        return {
            "investigation_summary": summary,
            "recommendations": recommendations,
            "investigation_status": "inconclusive",
            "investigation_confidence": float(state.get("investigation_confidence") or 0.0),
            "confidence_factors": confidence_factors,
            "supporting_evidence": state.get("supporting_evidence") or [],
            "inconclusive_reason": reason,
            "current_stage": "completed",
            "completed": True,
            "reasoning_steps": ["Generated safe inconclusive summary without overclaiming"],
            "agent_trace": [
                agent._agent_trace_event(
                    "report_generator", "inconclusive_summary", reason
                )
            ],
        }

    prompt = agent._create_report_prompt(state)
    print(f"Prompt length: {len(prompt)} chars")
    print("Sending report generation request to LLM...")
    _emit_terminal(agent, f"Prompt length: {len(prompt)} chars", progress=83)
    _emit_terminal(agent, "Sending report generation request to LLM...", progress=83)

    try:
        start_time = time.time()
        response = agent.llm.invoke(prompt)
        elapsed = time.time() - start_time

        print(f"\n[OK] Investigation Summary Generated ({elapsed:.2f}s)")
        print("-" * 60)
        print(response[:500] + ("..." if len(response) > 500 else ""))
        print("-" * 60)

        confidence_factors = list(state.get("confidence_factors") or [])
        if _is_prompt_echo_response(response):
            response = _build_evidence_bound_summary(agent, state)
            recommendations = agent._generate_default_recommendations(state)
            confidence_factors.append("LLM report response looked like prompt echo")
            _emit_terminal(
                agent,
                "[WARN] LLM report response looked like prompt echo; using evidence-bound summary.",
                progress=84,
                level="warning",
            )
        else:
            response = _append_evidence_boundary_notes(response, state)
            extracted_recommendations = agent._extract_recommendations(response)
            evidence_recommendations = agent._generate_default_recommendations(state)
            if extracted_recommendations:
                recommendations = agent_recommendations.dedupe_recommendations(
                    evidence_recommendations[:5] + extracted_recommendations
                )[:10]
            else:
                recommendations = evidence_recommendations

        print(f"\nExtracted Recommendations: {len(recommendations)} items")
        for idx, rec in enumerate(recommendations[:5], 1):
            print(f"  {idx}. {rec[:80]}...")
        _emit_terminal(
            agent,
            f"[OK] Investigation Summary Generated ({elapsed:.2f}s)",
            progress=84,
            level="success",
        )
        _emit_terminal(
            agent,
            f"Extracted Recommendations: {len(recommendations)} items",
            progress=84,
            level="success",
        )

        return {
            "investigation_summary": response,
            "recommendations": recommendations,
            "investigation_status": state.get("investigation_status") or "completed",
            "investigation_confidence": float(state.get("investigation_confidence") or 0.0),
            "confidence_factors": confidence_factors,
            "supporting_evidence": state.get("supporting_evidence") or [],
            "inconclusive_reason": state.get("inconclusive_reason") or "",
            "current_stage": "completed",
            "completed": True,
            "reasoning_steps": [
                "Generated comprehensive executive summary with ReAct reasoning"
            ],
            "agent_trace": [
                agent._agent_trace_event(
                    "report_generator", "completed", "Generated investigation summary"
                )
            ],
        }

    except Exception as e:
        print(f"[WARN] Error generating summary: {e}")
        _emit_terminal(
            agent,
            f"[WARN] Error generating summary: {e}",
            progress=84,
            level="warning",
        )
        import traceback

        print(traceback.format_exc())
        return {
            "investigation_summary": f"Error generating summary: {e}",
            "recommendations": agent._generate_default_recommendations(state),
            "investigation_status": "inconclusive",
            "investigation_confidence": float(state.get("investigation_confidence") or 0.0),
            "confidence_factors": state.get("confidence_factors")
            or ["Summary generation failed"],
            "supporting_evidence": state.get("supporting_evidence") or [],
            "inconclusive_reason": f"Summary generation failed: {e}",
            "current_stage": "error",
            "completed": True,
        }
