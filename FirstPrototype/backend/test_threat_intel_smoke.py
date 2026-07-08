"""Smoke test for the ThreatIntelToolkit.

Calls every provider once with a benign and a known-malicious IOC, prints a
PASS/FAIL summary so you can tell at a glance which integrations are healthy.

Run from backend/:
    python test_threat_intel_smoke.py
"""
from __future__ import annotations

import os
import sys
import time
from typing import Any, Callable, Dict, List, Tuple

# Allow running this script directly from the backend/ folder.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import settings  # noqa: E402
from modules.threat_intel import ThreatIntelToolkit  # noqa: E402


# Public, well-known IOCs - safe to query.
#   8.8.8.8        : Google DNS (should look benign everywhere)
#   185.220.101.1  : long-known Tor exit node (should be flagged by AbuseIPDB)
#   eicar.org      : EICAR test domain
#   example.com    : harmless reference
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# WannaCry SHA256 - permanently archived in MalwareBazaar, guaranteed hit.
WANNACRY_SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"

CASES: List[Tuple[str, str, str]] = [
    ("threatfox_lookup",         "ip",     "185.220.101.1"),
    ("threatfox_lookup",         "domain", "eicar.org"),
    ("malwarebazaar_lookup",     "sha256", EICAR_SHA256),
    ("malwarebazaar_lookup",     "sha256", WANNACRY_SHA256),  # expect signature=WannaCry
    ("urlhaus_lookup",           "url",    "http://example.com/"),
    ("alienvault_otx_lookup",    "ip",     "8.8.8.8"),
    ("alienvault_otx_lookup",    "domain", "eicar.org"),
    ("shodan_internetdb_lookup", "ip",     "8.8.8.8"),
    ("shodan_internetdb_lookup", "ip",     "185.220.101.1"),
    ("abuseipdb_lookup",         "ip",     "185.220.101.1"),
    ("virustotal_lookup",        "ip",     "8.8.8.8"),
]


def _call(toolkit: ThreatIntelToolkit, tool: str, ioc_type: str, ioc: str) -> Dict[str, Any]:
    fn: Callable[..., Dict[str, Any]] = getattr(toolkit, tool)
    if tool in {"malwarebazaar_lookup", "urlhaus_lookup",
                "shodan_internetdb_lookup", "abuseipdb_lookup"}:
        return fn(ioc)
    if tool == "threatfox_lookup":
        return fn(ioc, {"md5": "md5_hash", "sha256": "sha256_hash"}.get(ioc_type, ioc_type))
    if tool == "alienvault_otx_lookup":
        return fn(ioc, {"ip": "IPv4"}.get(ioc_type, ioc_type))
    if tool == "virustotal_lookup":
        return fn(ioc, "file" if ioc_type in {"md5", "sha256"} else ioc_type)
    raise ValueError(f"Unknown tool: {tool}")


def _verdict(result: Dict[str, Any]) -> Tuple[str, str]:
    """Return (PASS/FAIL/WARN, short_reason)."""
    if result.get("status") == "error" or result.get("error"):
        http = result.get("http_status")
        suffix = f" HTTP {http}" if http else ""
        return "FAIL", f"{result.get('error', 'error')}{suffix}"

    status = str(result.get("status") or "").lower()
    if status in {"not_found", "no_result", "no_exact_match"}:
        return "WARN", f"no data ({status})"

    if result.get("tool") == "shodan_internetdb" and status == "ok":
        return "PASS", (
            f"ports={len(result.get('ports', []))} "
            f"vulns={len(result.get('vulns', []))}"
        )
    if result.get("tool") == "abuseipdb" and status == "ok":
        return "PASS", f"score={result.get('abuse_confidence_score')}"
    if result.get("tool") == "virustotal" and status == "ok":
        return "PASS", (
            f"mal={result.get('malicious')} susp={result.get('suspicious')}"
        )
    if result.get("tool") == "alienvault_otx" and status == "ok":
        return "PASS", f"pulses={result.get('pulse_count', 0)}"
    if result.get("tool") == "malwarebazaar":
        sig = result.get("signature")
        if sig:
            return "PASS", f"status={status} signature={sig} type={result.get('file_type')}"
        items = result.get("data") or []
        return "PASS", f"status={status} items={len(items) if isinstance(items, list) else 'n/a'}"
    if result.get("tool") == "threatfox":
        items = result.get("data") or []
        family = result.get("malware_family")
        extra = f" family={family}" if family else ""
        return "PASS", f"status={status} items={len(items) if isinstance(items, list) else 'n/a'}{extra}"
    if result.get("tool") == "urlhaus":
        items = result.get("data") or []
        if isinstance(items, dict):
            items = [items]
        return "PASS", f"status={status} items={len(items) if isinstance(items, list) else 'n/a'}"

    return "PASS", f"status={status}"


def main() -> int:
    toolkit = ThreatIntelToolkit(api_keys={
        "abusech_api_key": settings.abusech_api_key,
        "alienvault_otx_api_key": settings.alienvault_otx_api_key,
        "abuseipdb_api_key": settings.abuseipdb_api_key,
        "virustotal_api_key": settings.virustotal_api_key,
    })

    print("\n" + "=" * 78)
    print(" Threat-Intel Toolkit Smoke Test")
    print("=" * 78)
    print(f" abuse.ch key:       {'set' if settings.abusech_api_key else 'MISSING'}")
    print(f" AlienVault OTX key: {'set' if settings.alienvault_otx_api_key else 'MISSING'}")
    print(f" AbuseIPDB key:      {'set' if settings.abuseipdb_api_key else 'MISSING'}")
    print(f" VirusTotal key:     {'set' if settings.virustotal_api_key else 'MISSING'}")
    print(f" Shodan InternetDB:  no key required")
    print("-" * 78)

    rows: List[Tuple[str, str, str, str, str, float]] = []
    for tool, ioc_type, ioc in CASES:
        start = time.time()
        try:
            result = _call(toolkit, tool, ioc_type, ioc)
            verdict, reason = _verdict(result)
        except Exception as e:  # pragma: no cover
            verdict, reason = "FAIL", f"exception: {e}"
        elapsed = time.time() - start
        rows.append((verdict, tool, ioc_type, ioc, reason, elapsed))
        time.sleep(1.0)  # be polite to free-tier providers

    print()
    print(f" {'RESULT':<6} {'TOOL':<28} {'TYPE':<6} {'IOC':<46} TIME    REASON")
    print(" " + "-" * 110)
    pass_n = fail_n = warn_n = 0
    for verdict, tool, ioc_type, ioc, reason, elapsed in rows:
        if verdict == "PASS":
            pass_n += 1
        elif verdict == "WARN":
            warn_n += 1
        else:
            fail_n += 1
        ioc_disp = (ioc[:43] + "...") if len(ioc) > 46 else ioc
        print(f" {verdict:<6} {tool:<28} {ioc_type:<6} {ioc_disp:<46} {elapsed:5.2f}s  {reason}")
    print()
    print(f" Totals: PASS={pass_n}  WARN={warn_n}  FAIL={fail_n}")
    return 0 if fail_n == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
