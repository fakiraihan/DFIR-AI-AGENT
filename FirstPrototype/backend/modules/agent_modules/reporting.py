"""Final summary/report node helpers for the DFIR agent."""

from typing import Any, Dict, Mapping
import time


def _emit_terminal(agent: Any, line: str, *, progress: int | None = None, level: str = "info") -> None:
    emit = getattr(agent, "_emit_terminal", None)
    if callable(emit):
        emit(line, progress=progress, level=level)


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
        summary = state.get("correlation_analysis") or state.get(
            "investigation_summary"
        ) or (
            "Investigasi bersifat inconclusive karena evidence yang tersedia belum cukup untuk membuat verdict ancaman final."
        )
        recommendations = state.get("recommendations") or agent._generate_default_recommendations(
            state
        )
        return {
            "investigation_summary": summary,
            "recommendations": recommendations,
            "investigation_status": "inconclusive",
            "investigation_confidence": float(state.get("investigation_confidence") or 0.0),
            "confidence_factors": state.get("confidence_factors") or [reason],
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

        recommendations = agent._extract_recommendations(response)
        if not recommendations:
            recommendations = agent._generate_default_recommendations(state)

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
            "confidence_factors": state.get("confidence_factors") or [],
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
