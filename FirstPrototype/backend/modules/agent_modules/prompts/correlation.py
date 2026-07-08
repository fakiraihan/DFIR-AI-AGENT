"""Correlation-analysis prompt builder."""

from typing import Any, Dict, List

from .common import AnomalySummarizer, PositiveCount, ToolResultPredicate


def create_correlation_prompt(
    anomalies: List[Dict[str, Any]],
    tool_results: List[Dict[str, Any]],
    *,
    summarize_anomaly_details: AnomalySummarizer,
    is_malicious_tool_result: ToolResultPredicate,
    is_suspicious_tool_result: ToolResultPredicate,
    safe_positive_count: PositiveCount,
) -> str:
    """Create prompt for correlation using a ReAct-style structure."""
    relevant_tool_results = [
        result
        for result in tool_results
        if result.get("status") != "skipped" and not result.get("skipped")
    ]

    threat_findings = []
    malicious_count = 0
    suspicious_count = 0

    prioritized_tool_results = sorted(
        relevant_tool_results,
        key=lambda item: (
            int(is_malicious_tool_result(item)),
            int(is_suspicious_tool_result(item)),
        ),
        reverse=True,
    )

    for result in prioritized_tool_results[:30]:
        if result.get("status") == "error":
            continue

        tool_name = result.get("tool", "unknown")
        ioc = result.get("ioc", "N/A")
        status = result.get("status", "checked")

        if is_malicious_tool_result(result):
            malicious_count += 1
            threat_findings.append(
                f"- **{tool_name}**: IOC `{ioc}` -> MALICIOUS | "
                f"Malware: {result.get('malware_family', 'unknown')} | "
                f"Threat: {result.get('threat_type', 'unknown')} | "
                f"Malicious detections: {safe_positive_count(result.get('malicious'))}"
            )
        elif is_suspicious_tool_result(result):
            suspicious_count += 1
            threat_findings.append(
                f"- **{tool_name}**: IOC `{ioc}` -> SUSPICIOUS | "
                f"Classification: {result.get('classification', 'unknown')} | "
                f"Suspicious detections: {safe_positive_count(result.get('suspicious'))}"
            )
        elif result.get("data"):
            threat_findings.append(
                f"- **{tool_name}**: IOC `{ioc}` -> Response available, no explicit threat signal | Status: {status}"
            )
        else:
            threat_findings.append(f"- **{tool_name}**: IOC `{ioc}` -> Clean/Unknown")

    findings_text = (
        "\n".join(threat_findings)
        if threat_findings
        else "Tidak ada temuan threat intelligence"
    )

    anomaly_details = []
    for idx, anomaly in enumerate(anomalies[:10], 1):
        detail_summary = summarize_anomaly_details(anomaly)
        detail_suffix = f" | {detail_summary}" if detail_summary else ""
        anomaly_details.append(
            f"{idx}. Window {anomaly.get('window_id')}: "
            f"{anomaly.get('actual_event', 'Unknown')[:80]}...{detail_suffix}"
        )
    anomaly_context = "\n".join(anomaly_details)

    return f"""# DFIR Correlation Analysis - ReAct Framework

Anda adalah Lead DFIR Analyst Security yang berpengalaman dalam cyber threat hunting.
Tugas: Korelasikan temuan anomali dengan threat intelligence untuk membangun hypothesis serangan.

## INPUT DATA

### Anomaly Detection Results
Total Anomalies: {len(anomalies)}
**Anomaly Windows:**
{anomaly_context}

### Threat Intelligence Results
Total Queries: {len(relevant_tool_results)}
- **Malicious IOCs:** {malicious_count}
- **Suspicious IOCs:** {suspicious_count}
- **Clean/Unknown:** {len(relevant_tool_results) - malicious_count - suspicious_count}

**Detailed Findings:**
{findings_text}

## REACT CORRELATION PROCESS

### THOUGHT 1: Analyze Threat Landscape
**Question:** Apa pola IOC yang teridentifikasi?
- Apakah ada IOC malicious yang confirmed?
- Malware family apa yang terlibat?
- Apakah ada clustering IOC (multiple IOC dari satu source)?

**Reasoning:** [Analisis pola threat intelligence]

### THOUGHT 2: Map to Anomalies
**Question:** Bagaimana IOC malicious berkorelasi dengan anomali log?
- Apakah anomali terjadi di timeframe yang sama?
- Apakah ada event sequence yang mencurigakan?
- Pola apa yang menunjukkan serangan terkoordinasi?

**Reasoning:** [Hubungkan IOC dengan anomaly windows]

### THOUGHT 3: Construct Attack Hypothesis
**Question:** Apa skenario serangan yang paling mungkin?
- Vektor serangan awal (initial access)?
- Teknik yang digunakan attacker?
- Tujuan serangan (objective)?

**Reasoning:** [Bangun hypothesis berdasarkan evidence]

## OUTPUT REQUIREMENTS

Provide structured correlation analysis in Bahasa Indonesia:

### 1. THREAT SUMMARY (2-3 kalimat)
Ringkas temuan threat intelligence dan tingkat ancaman.

### 2. CORRELATION FINDINGS (3-5 poin)
- Korelasi spesifik antara IOC malicious dengan anomali
- Evidence linking (window ID, IOC, threat type)
- Pattern identification

### 3. ATTACK HYPOTHESIS (2-3 paragraf)
- Kemungkinan attack vector
- Teknik yang digunakan (jika teridentifikasi)
- Attack progression/kill chain
- Objective estimation

### 4. CONFIDENCE ASSESSMENT
- Overall confidence: High/Medium/Low
- Key evidence supporting hypothesis
- Gaps in analysis

**IMPORTANT:**
- Fokus pada IOC malicious dan suspicious
- Gunakan evidence konkrit (window ID, IOC value, malware family)
- Jika tidak ada IOC malicious, analisis apakah anomali adalah false positive atau threat belum teridentifikasi
- Profesional dan faktual, hindari spekulasi berlebihan

Begin correlation analysis:"""
