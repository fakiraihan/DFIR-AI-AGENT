"""Investigation-report prompt builder."""

from typing import Any, Mapping

from .common import AnomalySummarizer, ToolResultPredicate


def create_report_prompt(
    state: Mapping[str, Any],
    *,
    summarize_anomaly_details: AnomalySummarizer,
    is_malicious_tool_result: ToolResultPredicate,
) -> str:
    """Create prompt for comprehensive report generation using ReAct pattern."""
    num_anomalies = len(state["anomalies"])
    num_iocs = len(state["iocs_extracted"])
    num_tools = len(state["tool_results"])

    malicious_iocs = []
    for result in state["tool_results"]:
        if is_malicious_tool_result(result):
            malicious_iocs.append(
                {
                    "ioc": result.get("ioc", "N/A"),
                    "type": result.get("ioc_type", "unknown"),
                    "malware": result.get("malware_family", "Unknown"),
                    "threat_type": result.get("threat_type", "Unknown"),
                }
            )

    reasoning_summary = "\n".join(
        [f"- {step[:150]}" for step in state.get("reasoning_steps", [])[-5:]]
    )

    correlation_analysis = state.get(
        "correlation_analysis", "Correlation analysis not available"
    )
    correlation_preview = (
        correlation_analysis[:1400] + "..."
        if len(correlation_analysis) > 1400
        else correlation_analysis
    )

    timeline_events = state.get("attack_timeline", [])
    timeline_summary = (
        f"{len(timeline_events)} events" if timeline_events else "Timeline not constructed"
    )

    anomaly_details = []
    for idx, anomaly in enumerate(state.get("anomalies", [])[:12], 1):
        detail_summary = summarize_anomaly_details(anomaly)
        detail_suffix = f" | {detail_summary}" if detail_summary else ""
        anomaly_details.append(
            f"{idx}. Window {anomaly.get('window_id', '-')}: "
            f"event={anomaly.get('actual_event', 'Unknown')} | "
            f"score={anomaly.get('anomaly_score', anomaly.get('score', 'N/A'))}"
            f"{detail_suffix}"
        )
    anomaly_evidence = (
        "\n".join(anomaly_details)
        if anomaly_details
        else "Tidak ada detail anomali tersedia."
    )

    timeline_details = []
    for idx, event in enumerate(timeline_events[:12], 1):
        timeline_details.append(
            f"{idx}. timestamp={event.get('timestamp', 'N/A')} | "
            f"event={event.get('event_template') or event.get('event') or 'Unknown'} | "
            f"details={event.get('description') or event.get('details') or 'N/A'}"
        )
    timeline_evidence = (
        "\n".join(timeline_details) if timeline_details else "Timeline belum terbentuk."
    )

    tool_result_details = []
    for idx, result in enumerate(state.get("tool_results", [])[:30], 1):
        tool_result_details.append(
            f"{idx}. tool={result.get('tool', 'unknown')} | "
            f"ioc={result.get('ioc') or result.get('ip') or result.get('url') or result.get('hash') or 'N/A'} | "
            f"classification={result.get('classification', 'N/A')} | "
            f"malicious={result.get('malicious', 'N/A')} | "
            f"suspicious={result.get('suspicious', 'N/A')} | "
            f"status={result.get('status', 'N/A')}"
        )
    tool_evidence = (
        "\n".join(tool_result_details)
        if tool_result_details
        else "Tidak ada hasil threat intelligence tersedia."
    )

    return f"""# DFIR Executive Summary Report - ReAct Framework

Anda adalah Chief Security Officer yang akan mempresentasikan hasil investigasi kepada stakeholder.
Tugas: Buat laporan investigasi DFIR yang PANJANG, KAYA INFORMASI, COMPREHENSIVE, ACTIONABLE, dan PROFESIONAL.

ATURAN OUTPUT WAJIB:
- Jawab HANYA dalam Bahasa Indonesia formal.
- Jangan membuat contoh log, IOC, timestamp, atau proses yang tidak ada di input.
- Jika evidence tidak cukup, tulis "belum cukup bukti" dan jelaskan gap datanya.
- Setiap klaim penting harus menyebut evidence: window ID, IOC, tool result, timeline, process/user/command line, atau anomaly score.
- Panjang target minimal 900 kata jika data mencukupi. Prioritaskan informasi dan penjelasan dibanding kreativitas.
- Output harus langsung berupa laporan final, bukan soal latihan, bukan template, dan bukan instruksi pengerjaan.

## INVESTIGATION METRICS

### Quantitative Data
- **Total Anomalies Detected:** {num_anomalies} windows
- **IOCs Extracted:** {num_iocs} indicators
- **Threat Intelligence Queries:** {num_tools} API calls
- **Malicious IOCs Confirmed:** {len(malicious_iocs)}
- **Attack Timeline:** {timeline_summary}

### Key Malicious IOCs
{chr(10).join([f"- {ioc['type'].upper()}: {ioc['ioc']} -> {ioc['malware']} ({ioc['threat_type']})" for ioc in malicious_iocs[:5]]) if malicious_iocs else "No malicious IOCs confirmed"}

### DeepLog Anomaly Evidence
{anomaly_evidence}

### Threat Intelligence Evidence
{tool_evidence}

### Timeline Evidence
{timeline_evidence}

### Correlation Analysis Summary
{correlation_preview}

### Investigation Reasoning Chain
{reasoning_summary}

## ANALYSIS CHECKLIST INTERNAL

Gunakan checklist ini hanya untuk berpikir, bukan untuk ditulis ulang:
- Severity harus mengikuti evidence: jumlah IOC malicious/suspicious, kualitas tool result, konteks log, timeline, dan gap data.
- Attack analysis harus menyebut event/window/IOC/timeline yang benar-benar tersedia.
- Impact assessment harus tetap "belum cukup bukti" bila tidak ada bukti compromise, exfiltration, atau objective achieved.
- Remediation harus berupa tindakan DFIR spesifik terhadap artifact yang terlihat.

## OUTPUT CONTRACT

Tulis laporan final dalam Bahasa Indonesia formal dengan heading berikut:

### 1. RINGKASAN EKSEKUTIF
Tulis tiga sampai empat paragraf naratif yang langsung menyimpulkan insiden, evidence utama, severity, confidence, limitasi, dan tindakan prioritas. Jangan menulis daftar pertanyaan atau kerangka penulisan.

### 2. TINGKAT SEVERITY
Tuliskan classification sebagai CRITICAL, HIGH, MEDIUM, atau LOW. Tuliskan confidence sebagai High, Medium, atau Low. Berikan justifikasi dua sampai tiga kalimat yang mengikat severity ke evidence.

### 3. INDIKATOR KOMPROMI UTAMA
Tuliskan IOC paling relevan yang benar-benar ada pada input. Untuk setiap IOC, sebutkan tipe, hasil enrichment, evidence pendukung, dan tindakan yang tepat. Jika tidak ada IOC malicious terkonfirmasi, katakan dengan jelas.

### 4. MITRE ATT&CK MAPPING
Tuliskan mapping hanya jika didukung event, process, registry, network, share, atau artifact lain pada evidence. Jika tidak cukup bukti untuk technique tertentu, tulis bahwa technique belum dapat ditetapkan.

### 5. ATTACK TIMELINE
Susun kronologi dari timeline dan window anomali yang tersedia. Jangan menciptakan tahap initial compromise, lateral movement, objective achieved, atau exfiltration jika tidak ada evidence.

### 6. DAMPAK POTENSIAL
Bedakan impact yang terbukti, impact potensial, dan area yang belum dapat dinilai. Jangan menaikkan anomaly count menjadi compromise count.

### 7. RECOMMENDATIONS
Tulis rekomendasi prioritas untuk immediate, short-term, dan long-term. Setiap rekomendasi harus menyebut artifact nyata seperti window ID, EventID, user, host, process, path, registry, share, IOC, atau tool result.

## WRITING GUIDELINES

**Tone:** Profesional, faktual, actionable
**Language:** Bahasa Indonesia formal untuk laporan Security
**Evidence-based:** Setiap claim penting harus didukung data
**Actionable:** Recommendations harus spesifik dan implementable
**Balanced:** Jika tidak ada threat confirmed, nyatakan bahwa evidence belum cukup untuk verdict malicious final

**AVOID:**
- Mengulang prompt, checklist, atau instruksi ini
- Menulis placeholder, contoh format, daftar pertanyaan, atau catatan pengerjaan
- Spekulasi tanpa evidence
- Teknis jargon berlebihan
- Understatement threat jika genuine
- Overstatement threat jika evidence belum cukup

Tulis laporan final sekarang dalam Bahasa Indonesia. Mulai langsung dari heading pertama.

### 1. RINGKASAN EKSEKUTIF
"""
