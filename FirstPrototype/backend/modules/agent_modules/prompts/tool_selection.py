"""Threat-intel tool-selection prompt builder."""

from typing import Any, Dict, List


def create_tool_selection_prompt(iocs: List[Dict[str, Any]]) -> str:
    """Create prompt for tool selection using the full threat-intel toolset."""
    iocs_text = "\n".join(
        [f"- {ioc['type'].upper()}: {ioc['value']}" for ioc in iocs[:15]]
    )

    return f"""# DFIR Tool Selection - Threat Intel Framework

Anda adalah Security Analyst yang ahli dalam Digital Forensics & Incident Response.
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
- Input: MD5/SHA256 file hash saja
- Kelebihan: file sample intel, signature, tags

3) urlhaus_lookup
- Input: URL saja
- Kelebihan: URL malware hosting status dan payload context

4) alienvault_otx_lookup
- Input: domain/url/hash saja (BUKAN IP — jangan gunakan untuk IOC tipe IP)
- Kelebihan: pulse komunitas, reputasi, IOC relasi untuk domain, URL, dan file hash

5) abuseipdb_lookup
- Input: IP saja
- Kelebihan: abuse confidence score (0-100), report history, TOR/whitelist flag

6) virustotal_lookup
- Input: IP/domain/url/file hash
- Kelebihan: agregasi multi-engine reputation

## MAPPING GUIDELINES
- IP: WAJIB gunakan HANYA abuseipdb_lookup, threatfox_lookup, dan virustotal_lookup. DILARANG menggunakan alienvault_otx_lookup untuk IP.
- Domain: WAJIB gunakan threatfox_lookup, alienvault_otx_lookup, dan virustotal_lookup.
- URL: WAJIB gunakan urlhaus_lookup, alienvault_otx_lookup, threatfox_lookup, dan virustotal_lookup.
- MD5/SHA256: WAJIB gunakan malwarebazaar_lookup, alienvault_otx_lookup, virustotal_lookup, dan threatfox_lookup.

## OUTPUT FORMAT
Gunakan format ini (satu baris per pemanggilan tool):
ip:192.168.1.100 -> abuseipdb_lookup
ip:192.168.1.100 -> threatfox_lookup
ip:192.168.1.100 -> virustotal_lookup
(HANYA 3 tool untuk IP — tidak lebih, alienvault_otx_lookup DILARANG untuk IP)
domain:evil.com -> threatfox_lookup
domain:evil.com -> alienvault_otx_lookup
domain:evil.com -> virustotal_lookup
sha256:abc123... -> malwarebazaar_lookup
sha256:abc123... -> alienvault_otx_lookup
sha256:abc123... -> virustotal_lookup
sha256:abc123... -> threatfox_lookup
url:http://bad.com/payload.exe -> urlhaus_lookup
url:http://bad.com/payload.exe -> alienvault_otx_lookup
url:http://bad.com/payload.exe -> threatfox_lookup
url:http://bad.com/payload.exe -> virustotal_lookup

Pilih 2-4 tools per IOC sesuai mapping di atas dan hanya gunakan nama tool dari daftar di atas."""
