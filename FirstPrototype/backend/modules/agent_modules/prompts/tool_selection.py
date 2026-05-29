"""Threat-intel tool-selection prompt builder."""

from typing import Any, Dict, List


def create_tool_selection_prompt(iocs: List[Dict[str, Any]]) -> str:
    """Create prompt for tool selection using the full threat-intel toolset."""
    iocs_text = "\n".join(
        [f"- {ioc['type'].upper()}: {ioc['value']}" for ioc in iocs[:15]]
    )

    return f"""# DFIR Tool Selection - Threat Intel Framework

Anda adalah Security Analyst TNI AL yang ahli dalam Digital Forensics & Incident Response.
Tugas: pilih threat intelligence tools yang paling tepat untuk setiap IOC.

## CONTEXT
Total IOC Extracted: {len(iocs)}

**IOC List:**
{iocs_text}

## AVAILABLE TOOLS

1) threatfox_lookup
- Input: IP/domain/url/hash
- Kelebihan: IOC abuse.ch feed, malware family, threat type

2) malwarebazaar_lookup
- Input: MD5/SHA256 file hash
- Kelebihan: file sample intel, signature, tags

3) urlhaus_lookup
- Input: URL saja
- Kelebihan: URL malware hosting status dan payload context

4) alienvault_otx_lookup
- Input: IP/domain/url/hash
- Kelebihan: pulse komunitas, reputasi, IOC relasi

5) greynoise_lookup
- Input: IP saja
- Kelebihan: klasifikasi scanner/noise vs malicious

6) virustotal_lookup
- Input: IP/domain/url/file hash
- Kelebihan: agregasi multi-engine reputation

## MAPPING GUIDELINES
- IP: prioritaskan greynoise_lookup dan threatfox_lookup; tambahkan alienvault_otx_lookup atau virustotal_lookup bila perlu reputasi tambahan.
- Domain: prioritaskan threatfox_lookup, alienvault_otx_lookup, atau virustotal_lookup.
- URL: prioritaskan urlhaus_lookup lalu threatfox_lookup atau virustotal_lookup.
- MD5/SHA256: prioritaskan malwarebazaar_lookup lalu virustotal_lookup; threatfox_lookup dan alienvault_otx_lookup boleh dipakai sebagai pelengkap.

## OUTPUT FORMAT
Gunakan format ini (satu baris per pemanggilan tool):
ip:192.168.1.100 -> greynoise_lookup
ip:192.168.1.100 -> alienvault_otx_lookup
domain:evil.com -> virustotal_lookup
domain:evil.com -> threatfox_lookup
sha256:abc123... -> virustotal_lookup
sha256:abc123... -> malwarebazaar_lookup
url:http://bad.com/payload.exe -> urlhaus_lookup

Pilih 1-3 tools per IOC dan hanya gunakan nama tool dari daftar di atas."""
