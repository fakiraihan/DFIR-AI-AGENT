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

Anda adalah Chief Security Officer TNI AL yang akan mempresentasikan hasil investigasi kepada stakeholder.
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

## REACT REPORT GENERATION PROCESS

### THOUGHT 1: Incident Classification
**Question:** Apa tingkat severity insiden ini?
- Berapa banyak IOC malicious terconfirm?
- Apakah ada indikasi data exfiltration atau system compromise?
- Seberapa besar scope dampak?

**Classification Criteria:**
- **CRITICAL:** Multiple confirmed malware, C2 communication, data exfiltration evidence
- **HIGH:** Confirmed malware presence, suspicious IOCs, potential compromise
- **MEDIUM:** Some suspicious activity, unclear threat, possible false positives
- **LOW:** Mostly benign anomalies, no confirmed threats

### THOUGHT 2: Attack Analysis
**Question:** Apa yang sebenarnya terjadi?
- Apa attack vector yang digunakan?
- Teknik apa yang teridentifikasi (MITRE ATT&CK)?
- Apakah ini targeted attack atau opportunistic?

### THOUGHT 3: Impact Assessment
**Question:** Apa dampak dan risikonya?
- System/data apa yang terpengaruh?
- Apakah attacker berhasil achieve objectives?
- Apa risiko lanjutan jika tidak ditangani?

### THOUGHT 4: Remediation Priority
**Question:** Apa yang harus dilakukan immediately?
- Isolation/containment?
- IOC blocking?
- Forensics collection?
- System hardening?

## OUTPUT REQUIREMENTS

Generate comprehensive report dalam Bahasa Indonesia dengan struktur:

### 1. RINGKASAN EKSEKUTIF (Executive Summary)
**[3-4 paragraf profesional]**

Paragraf 1: **Incident Overview**
- Kapan investigasi dilakukan
- Berapa anomali dan IOC ditemukan
- Verdict: Apakah ini genuine threat atau false positive dominan

Paragraf 2: **Threat Identification**
- Malware family atau threat actor (jika teridentifikasi)
- Attack vector dan teknik yang digunakan
- IOC malicious yang terconfirm

Paragraf 3: **Impact Assessment**
- Scope compromise (jika ada)
- Data/systems yang terpengaruh
- Potential damage atau risk

Paragraf 4: **Recommended Actions**
- Immediate actions (containment)
- Short-term mitigation
- Long-term improvements

### 2. TINGKAT SEVERITY
**Classification:** [CRITICAL/HIGH/MEDIUM/LOW]
**Confidence Level:** [High/Medium/Low]

**Justification:** [2-3 kalimat explaining severity rating]

### 3. INDIKATOR KOMPROMI UTAMA (Key IOCs)
List 5-10 IOC paling penting dengan konteks:
- IOC value
- Type (IP/domain/hash/URL)
- Threat classification
- Recommended action (block/monitor/investigate)

### 4. MITRE ATT&CK MAPPING (Jika Applicable)
Map temuan ke MITRE ATT&CK Framework:
- **Tactic:** [e.g., Initial Access, Execution, Persistence]
- **Technique:** [e.g., T1566 Phishing, T1059 Command Execution]
- **Evidence:** [Supporting evidence dari logs/IOCs]

### 5. ATTACK TIMELINE (Jika Teridentifikasi)
Kronologi serangan:
- Initial compromise
- Lateral movement (if any)
- Objective achievement
- Detection point

### 6. DAMPAK POTENSIAL
- **Technical Impact:** System compromise, data exposure, service disruption
- **Business Impact:** Operational impact, reputational risk, compliance issues
- **Risk Rating:** Quantify risk level

### 7. RECOMMENDATIONS (Prioritized)
**Immediate (0-24 hours):**
1. [Action item with specific steps]
2. [Action item with specific steps]

**Short-term (1-7 days):**
1. [Mitigation measure]
2. [Investigation follow-up]

**Long-term (Strategic):**
1. [Security improvement]
2. [Process enhancement]

## WRITING GUIDELINES

**Tone:** Profesional, faktual, actionable
**Language:** Bahasa Indonesia formal (untuk laporan TNI AL)
**Evidence-based:** Setiap claim harus didukung data
**Actionable:** Recommendations harus spesifik dan implementable
**Balanced:** Jika tidak ada threat confirmed, clearly state itu adalah false positive atau benign activity

**AVOID:**
- Spekulasi tanpa evidence
- Teknis jargon berlebihan (explain untuk non-technical stakeholders)
- Understatement threat (if genuine)
- Overstatement threat (if false positive)

Tulis laporan final sekarang dalam Bahasa Indonesia. Jangan awali dengan penjelasan bahwa Anda akan menulis laporan. Jangan tampilkan placeholder.

### 1. RINGKASAN EKSEKUTIF
"""
